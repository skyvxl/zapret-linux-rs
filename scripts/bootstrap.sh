#!/usr/bin/env bash

set -uo pipefail

readonly MIN_RUST_MAJOR=1
readonly MIN_RUST_MINOR=88

declare -a MISSING=()
declare -a APT_PACKAGES=()

add_package() {
    local candidate=$1 current
    for current in "${APT_PACKAGES[@]}"; do
        [[ $current == "$candidate" ]] && return 0
    done
    APT_PACKAGES+=("$candidate")
}

add_missing() {
    MISSING+=("$1")
    shift
    local package
    for package in "$@"; do
        add_package "$package"
    done
}

add_cargo_home_to_path() {
    local cargo_home=${CARGO_HOME:-${HOME:-}/.cargo}
    if [[ $cargo_home == /* && -x $cargo_home/bin/cargo ]]; then
        case :$PATH: in
            *:"$cargo_home/bin":*) ;;
            *) PATH=$cargo_home/bin:$PATH ;;
        esac
    fi
    export PATH
}

add_standard_sbin_to_path() {
    local pair bin_dir sbin_dir
    local -a pairs=(
        "/usr/local/bin:/usr/local/sbin"
        "/usr/bin:/usr/sbin"
        "/bin:/sbin"
    )
    for pair in "${pairs[@]}"; do
        bin_dir=${pair%%:*}
        sbin_dir=${pair#*:}
        case :$PATH: in
            *:"$bin_dir":*)
                [[ -d $sbin_dir ]] || continue
                case :$PATH: in
                    *:"$sbin_dir":*) ;;
                    *) PATH=$PATH:$sbin_dir ;;
                esac
                ;;
        esac
    done
    export PATH
}

tool_version_is_supported() {
    local tool_path=$1 version_line version major minor rest
    version_line=$("$tool_path" --version 2>/dev/null) || return 1
    read -r _ version _ <<< "$version_line"
    [[ $version =~ ^[0-9]+\.[0-9]+([.][0-9]+)? ]] || return 1
    IFS=. read -r major minor rest <<< "$version"
    ((major > MIN_RUST_MAJOR || (major == MIN_RUST_MAJOR && minor >= MIN_RUST_MINOR)))
}

have_any_command() {
    local name
    for name in "$@"; do
        command -v "$name" >/dev/null 2>&1 && return 0
    done
    return 1
}

inspect_dependencies() {
    MISSING=()
    APT_PACKAGES=()
    add_standard_sbin_to_path
    add_cargo_home_to_path

    local cargo_path= rustc_path=
    cargo_path=$(command -v cargo 2>/dev/null || true)
    rustc_path=$(command -v rustc 2>/dev/null || true)
    if [[ -z $cargo_path || -z $rustc_path ]] \
        || ! tool_version_is_supported "$cargo_path" \
        || ! tool_version_is_supported "$rustc_path"; then
        add_missing "Rust/Cargo версии 1.88 или новее" cargo rustc
    fi
    have_any_command cc gcc clang || add_missing "компилятор и линкер C" build-essential
    command -v curl >/dev/null 2>&1 || add_missing "curl" curl
    [[ -r /etc/ssl/certs/ca-certificates.crt ]] || add_missing "корневые сертификаты CA" ca-certificates
    command -v tar >/dev/null 2>&1 || add_missing "tar" tar
    command -v gzip >/dev/null 2>&1 || add_missing "gzip" gzip
    command -v nft >/dev/null 2>&1 || add_missing "nftables" nftables
    command -v ip >/dev/null 2>&1 || add_missing "iproute2" iproute2
    if ! command -v iptables-legacy-save >/dev/null 2>&1 || ! command -v ip6tables-legacy-save >/dev/null 2>&1; then
        add_missing "iptables-legacy-save и ip6tables-legacy-save" iptables
    fi
    command -v sudo >/dev/null 2>&1 || add_missing "sudo" sudo
}

print_missing() {
    local item
    printf 'Не готовы системные зависимости:\n' >&2
    for item in "${MISSING[@]}"; do
        printf '  - %s\n' "$item" >&2
    done
}

read_os_field() {
    local wanted=$1 file=/etc/os-release
    local key value
    [[ -r $file ]] || return 1
    while IFS='=' read -r key value; do
        [[ $key == "$wanted" ]] || continue
        if [[ $value == \"*\" && $value == *\" ]]; then
            value=${value:1:${#value}-2}
        elif [[ $value == \'*\' && $value == *\' ]]; then
            value=${value:1:${#value}-2}
        fi
        printf '%s\n' "$value"
        return 0
    done < "$file"
    return 1
}

is_apt_family() {
    local os_id os_like word
    os_id=$(read_os_field ID 2>/dev/null || true)
    os_like=$(read_os_field ID_LIKE 2>/dev/null || true)
    [[ $os_id == debian || $os_id == ubuntu ]] && return 0
    for word in $os_like; do
        [[ $word == debian || $word == ubuntu ]] && return 0
    done
    return 1
}

print_command() {
    printf 'Команда: '
    printf '%q ' "$@"
    printf '\n'
}

install_apt_dependencies() {
    command -v apt-get >/dev/null 2>&1 || {
        printf 'Ошибка: apt-get не найден в системе семейства Debian.\n' >&2
        return 1
    }

    local -a privilege=()
    if ((EUID != 0)); then
        command -v sudo >/dev/null 2>&1 || {
            printf 'Ошибка: для установки нужен sudo; установите его от root и повторите команду.\n' >&2
            return 1
        }
        privilege=(sudo --)
    fi

    printf 'Будут установлены недостающие пакеты apt:'
    printf ' %s' "${APT_PACKAGES[@]}"
    printf '\n'

    local -a update_command=("${privilege[@]}" apt-get update)
    local -a install_command=("${privilege[@]}" apt-get install --no-install-recommends -y "${APT_PACKAGES[@]}")
    print_command "${update_command[@]}"
    "${update_command[@]}" || return $?
    print_command "${install_command[@]}"
    "${install_command[@]}" || return $?
}

usage() {
    printf 'Использование: bootstrap.sh --check|--install\n' >&2
}

case ${1:-} in
    --check)
        [[ $# == 1 ]] || { usage; exit 2; }
        inspect_dependencies
        if ((${#MISSING[@]})); then
            print_missing
            exit 1
        fi
        printf 'Системные зависимости готовы.\n'
        ;;
    --install)
        [[ $# == 1 ]] || { usage; exit 2; }
        inspect_dependencies
        if ((${#MISSING[@]} == 0)); then
            printf 'Системные зависимости уже готовы.\n'
            exit 0
        fi
        print_missing
        if ! is_apt_family; then
            printf 'Ошибка: автоматическая установка поддерживается только для Debian/Ubuntu и производных.\n' >&2
            exit 1
        fi
        install_apt_dependencies || exit $?
        inspect_dependencies
        if ((${#MISSING[@]})); then
            print_missing
            printf 'Ошибка: после установки часть зависимостей всё ещё недоступна.\n' >&2
            exit 1
        fi
        printf 'Системные зависимости готовы.\n'
        ;;
    *)
        usage
        exit 2
        ;;
esac
