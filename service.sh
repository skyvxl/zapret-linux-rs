#!/usr/bin/env bash

set -uo pipefail

print_help() {
    printf '%s\n' \
        'zapret-linux-rs — удобный запуск' \
        '' \
        'Использование:' \
        '  ./service.sh                 открыть интерактивное меню' \
        '  ./service.sh menu            открыть интерактивное меню' \
        '  ./service.sh build           собрать текущий исходный код' \
        '  ./service.sh deps --check    проверить системные зависимости' \
        '  ./service.sh deps --install  установить недостающие зависимости' \
        '  ./service.sh КОМАНДА ...     передать команду интерфейсу Rust' \
        '  ./service.sh --help          показать эту справку' \
        '' \
        'Обычные команды интерфейса: setup, run, diagnose, config, doctor, service.'
}

die() {
    printf 'Ошибка: %s\n' "$*" >&2
    exit 1
}

resolve_launcher() {
    local path=$1 link directory
    if [[ $path != */* ]]; then
        path=$(command -v -- "$path") || return 1
    fi
    [[ $path == /* ]] || path=$PWD/$path

    local links=0
    while [[ -L $path ]]; do
        ((links += 1))
        ((links <= 40)) || return 1
        link=$(readlink -- "$path") || return 1
        directory=${path%/*}
        if [[ $link == /* ]]; then
            path=$link
        else
            path=$directory/$link
        fi
    done

    directory=${path%/*}
    directory=$(cd -P -- "$directory" 2>/dev/null && pwd) || return 1
    printf '%s/%s\n' "$directory" "${path##*/}"
}

find_cargo() {
    local found cargo_home
    cargo_home=${CARGO_HOME:-${HOME:-}/.cargo}
    if [[ $cargo_home == /* && -x $cargo_home/bin/cargo ]]; then
        printf '%s\n' "$cargo_home/bin/cargo"
        return 0
    fi
    if found=$(command -v cargo 2>/dev/null) && [[ -x $found ]]; then
        printf '%s\n' "$found"
        return 0
    fi
    return 1
}

find_rustc() {
    local cargo_dir=$1 found cargo_home
    if [[ -x $cargo_dir/rustc ]]; then
        printf '%s\n' "$cargo_dir/rustc"
        return 0
    fi
    cargo_home=${CARGO_HOME:-${HOME:-}/.cargo}
    if [[ $cargo_home == /* && -x $cargo_home/bin/rustc ]]; then
        printf '%s\n' "$cargo_home/bin/rustc"
        return 0
    fi
    if found=$(command -v rustc 2>/dev/null) && [[ -x $found ]]; then
        printf '%s\n' "$found"
        return 0
    fi
    return 1
}

rust_host_target() {
    local rustc=$1 verbose line host=
    verbose=$("$rustc" -vV 2>/dev/null) || return 1
    while IFS= read -r line; do
        [[ $line == 'host: '* ]] || continue
        host=${line#host: }
        break
    done <<< "$verbose"
    [[ $host =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
    printf '%s\n' "$host"
}

canonicalize_absolute_path() {
    local input=$1 part candidate physical tail=
    local -a input_parts=() clean_parts=()
    [[ $input == /* ]] || return 1
    IFS=/ read -r -a input_parts <<< "${input#/}"
    for part in "${input_parts[@]}"; do
        case $part in
            ''|.) ;;
            ..)
                ((${#clean_parts[@]})) && unset 'clean_parts[-1]'
                ;;
            *) clean_parts+=("$part") ;;
        esac
    done
    candidate=/
    for part in "${clean_parts[@]}"; do
        [[ $candidate == / ]] && candidate=/$part || candidate=$candidate/$part
    done

    while [[ ! -d $candidate ]]; do
        [[ $candidate != / ]] || return 1
        tail=/${candidate##*/}$tail
        candidate=${candidate%/*}
        [[ -n $candidate ]] || candidate=/
    done
    physical=$(cd -P -- "$candidate" 2>/dev/null && pwd) || return 1
    [[ $physical == / ]] && printf '/%s\n' "${tail#/}" || printf '%s%s\n' "$physical" "$tail"
}

launcher=$(resolve_launcher "$0") || die "не удалось определить настоящий путь service.sh"
project_dir=${launcher%/*}

case ${1:-} in
    --help|-h)
        print_help
        exit 0
        ;;
esac

bootstrap=$project_dir/scripts/bootstrap.sh
[[ -f $bootstrap ]] || die "не найден обязательный файл $bootstrap"
[[ -r $bootstrap ]] || die "нет доступа для чтения $bootstrap"

if ((EUID == 0)); then
    die "не запускайте service.sh через sudo; повторите команду от обычного пользователя"
fi

if [[ ${1:-} == deps ]]; then
    [[ $# == 2 ]] || die "использование: ./service.sh deps --check|--install"
    case $2 in
        --check|--install)
            exec /bin/bash "$bootstrap" "$2"
            ;;
        *)
            die "использование: ./service.sh deps --check|--install"
            ;;
    esac
fi

if ! /bin/bash "$bootstrap" --check >&2; then
    if [[ -t 0 ]]; then
        printf 'Подготовить недостающие зависимости сейчас? [y/N] ' >&2
        answer=
        IFS= read -r answer || answer=
        case $answer in
            y|Y|yes|YES|да|Да|ДА)
                /bin/bash "$bootstrap" --install >&2 || exit $?
                ;;
            *)
                printf 'Установка отменена. Запустите: %s deps --install\n' "$launcher" >&2
                exit 1
                ;;
        esac
    else
        printf 'Запустите подготовку явно: %s deps --install\n' "$launcher" >&2
        exit 1
    fi
fi

cargo=$(find_cargo) || die "Cargo не найден; запустите: $launcher deps --install"
cargo_dir=${cargo%/*}
PATH=$cargo_dir:$PATH
export PATH
rustc=$(find_rustc "$cargo_dir") || die "rustc не найден рядом с выбранным Cargo"
host_target=$(rust_host_target "$rustc") || die "не удалось определить host target через rustc -vV"

# Cargo creates the application cache hierarchy. Keep every newly created path private;
# existing paths are neither chmodded nor otherwise taken over here.
umask 077

if [[ -n ${CARGO_TARGET_DIR:-} ]]; then
    target_dir=$CARGO_TARGET_DIR
    [[ $target_dir == /* ]] || die "CARGO_TARGET_DIR должен быть абсолютным внешним путём"
else
    cache_home=${XDG_CACHE_HOME:-${HOME:-}/.cache}
    [[ $cache_home == /* ]] || die "XDG_CACHE_HOME должен быть абсолютным путём"
    target_dir=$cache_home/zapret-linux-rs/build
fi

canonical_target=$(canonicalize_absolute_path "$target_dir") || die "не удалось проверить каталог сборки: $target_dir"
case $canonical_target/ in
    "$project_dir"/*)
        die "каталог сборки должен находиться вне исходного checkout: $target_dir"
        ;;
esac
target_dir=$canonical_target

build_command=(
    "$cargo" build --locked
    --manifest-path "$project_dir/Cargo.toml"
    --target-dir "$target_dir"
    --target "$host_target"
    --bin zapret-linux-rs
)
printf 'Сборка текущего исходного кода...\n' >&2
"${build_command[@]}"
build_status=$?
((build_status == 0)) || exit "$build_status"

current_binary=$target_dir/$host_target/debug/zapret-linux-rs
[[ -x $current_binary ]] || die "Cargo завершился без ожидаемого файла $current_binary"

if [[ ${1:-} == build ]]; then
    printf 'Готово: %s\n' "$current_binary"
    exit 0
fi

export ZAPRET_LAUNCHER=$launcher
if (($# == 0)); then
    exec "$current_binary" ui
fi
if (($# == 1)) && [[ $1 == menu ]]; then
    exec "$current_binary" ui
fi
exec "$current_binary" ui "$@"
