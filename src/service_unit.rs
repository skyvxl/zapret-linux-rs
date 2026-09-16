pub const NAME: &str = "zapret-linux-rs.service";
pub const UNIT: &str = "/etc/systemd/system/zapret-linux-rs.service";
pub fn text() -> &'static str {
    r#"[Unit]
Description=zapret-linux-rs packet queue controller
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=notify
NotifyAccess=main
User=root
Group=root
UMask=0077
WorkingDirectory=/opt/zapret-linux-rs
StateDirectory=zapret-linux-rs
StateDirectoryMode=0700
ExecStartPre=/opt/zapret-linux-rs/bin/zapret-linux-rs state recover --state-dir /var/lib/zapret-linux-rs --nft /opt/zapret-linux-rs/bin/nft --timeout-ms 5000 --allow-previous-boot
ExecStart=/opt/zapret-linux-rs/bin/zapret-linux-rs run --host --systemd-notify --config /opt/zapret-linux-rs/config.env --strategies /opt/zapret-linux-rs/strategies --assets /opt/zapret-linux-rs/assets --nfqws /opt/zapret-linux-rs/bin/nfqws --nft /opt/zapret-linux-rs/bin/nft --iptables-save /opt/zapret-linux-rs/bin/iptables-legacy-save --ip6tables-save /opt/zapret-linux-rs/bin/ip6tables-legacy-save --state-dir /var/lib/zapret-linux-rs --timeout-ms 5000
ExecStopPost=/opt/zapret-linux-rs/bin/zapret-linux-rs state recover --state-dir /var/lib/zapret-linux-rs --nft /opt/zapret-linux-rs/bin/nft --timeout-ms 5000 --allow-previous-boot
KillMode=mixed
KillSignal=SIGTERM
SendSIGKILL=yes
TimeoutStartSec=120
TimeoutStopSec=60
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zapret-linux-rs

[Install]
WantedBy=multi-user.target
"#
}
