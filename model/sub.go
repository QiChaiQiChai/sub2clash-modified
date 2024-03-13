package model

// type Subscription struct {
// 	Port               int                     `yaml:"port,omitempty"`
// 	SocksPort          int                     `yaml:"socks-port,omitempty"`
// 	AllowLan           bool                    `yaml:"allow-lan"`
// 	Mode               string                  `yaml:"mode,omitempty"`
// 	LogLevel           string                  `yaml:"logger-level,omitempty"`
// 	ExternalController string                  `yaml:"external-controller,omitempty"`
// 	Proxies            []Proxy                 `yaml:"proxies,omitempty"`
// 	ProxyGroups        []ProxyGroup            `yaml:"proxy-groups,omitempty"`
// 	Rules              []string                `yaml:"rules,omitempty"`
// 	RuleProviders      map[string]RuleProvider `yaml:"rule-providers,omitempty,omitempty"`
// }

type NodeList struct {
	Proxies []Proxy `yaml:"proxies,omitempty"`
}

type Subscription struct {
	Mode                  string   `yaml:"mode,omitempty" json:"mode"`
	IPv6                  bool     `yaml:"ipv6,omitempty" json:"ipv6"`
	MixedPort             int      `yaml:"mixed-port,omitempty" json:"mixed-port"`
	AllowLan              bool     `yaml:"allow-lan,omitempty" json:"allow-lan"`
	LogLevel              string   `yaml:"log-level,omitempty" json:"log-level"`
	Interface             string   `yaml:"interface-name,omitempty"`
	Port                  int      `yaml:"port,omitempty" json:"port"`
	SocksPort             int      `yaml:"socks-port,omitempty" json:"socks-port"`
	RedirPort             int      `yaml:"redir-port,omitempty" json:"redir-port"`
	TProxyPort            int      `yaml:"tproxy-port,omitempty" json:"tproxy-port"`
	Secret                string   `yaml:"secret,omitempty"`
	ExternalController    string   `yaml:"external-controller,omitempty"`
	ExternalUI            string   `yaml:"external-ui,omitempty"`
	KeepAliveInterval       int    `yaml:"keep-alive-interval,omitempty"`
	FindProcessMode         string `yaml:"find-process-mode,omitempty" json:"find-process-mode"`
	ExternalControllerTLS string   `yaml:"external-controller-tls,omitempty"`
	ExternalUIName        string   `yaml:"external-ui-name,omitempty" json:"external-ui-name"`
	ExternalUIURL         string   `yaml:"external-ui-url,omitempty" json:"external-ui-url"`
	UnifiedDelay          bool     `yaml:"unified-delay,omitempty" json:"unified-delay"`
	TCPConcurrent           bool   `yaml:"tcp-concurrent,omitempty" json:"tcp-concurrent"`
	Authentication        []string `yaml:"authentication,omitempty" json:"authentication"`
	SkipAuthPrefixes      []string `yaml:"skip-auth-prefixes,omitempty"`
	RawTLS        TLS                       `yaml:"tls,omitempty"`
	GlobalClientFingerprint string `yaml:"global-client-fingerprint,omitempty"`
	GeodataMode             bool   `yaml:"geodata-mode,omitempty" json:"geodata-mode"`
	GeoAutoUpdate           bool   `yaml:"geo-auto-update,omitempty" json:"geo-auto-update"`
	GeoUpdateInterval       int    `yaml:"geo-update-interval,omitempty" json:"geo-update-interval"`
	GeodataLoader           string `yaml:"geodata-loader,omitempty" json:"geodata-loader"`
	GeositeMatcher          string `yaml:"geosite-matcher,omitempty" json:"geosite-matcher"`
	GeoXUrl       GeoXUrl                   `yaml:"geox-url,omitempty"`
	GlobalUA                string `yaml:"global-ua,omitempty"`
	Profile       Profile                   `yaml:"profile,omitempty"`
	LanAllowedIPs         []string `yaml:"lan-allowed-ips,omitempty"`
	LanDisAllowedIPs      []string `yaml:"lan-disallowed-ips,omitempty"`

	ShadowSocksConfig     string   `yaml:"ss-config,omitempty"`
	VmessConfig           string   `yaml:"vmess-config,omitempty"`
	InboundTfo            bool     `yaml:"inbound-tfo,omitempty"`
	InboundMPTCP          bool     `yaml:"inbound-mptcp,omitempty"`
	BindAddress           string   `yaml:"bind-address,omitempty" json:"bind-address"`
	RoutingMark           int      `yaml:"routing-mark,omitempty"`
	//Tunnels                 []LC.Tunnel       `yaml:"tunnels,omitempty"`

	Sniffer       RawSniffer                `yaml:"sniffer,omitempty" json:"sniffer"`
	Hosts         map[string]any            `yaml:"hosts,omitempty" json:"hosts"`
	NTP           RawNTP                    `yaml:"ntp,omitempty" json:"ntp"`
	Tun           RawTun                    `yaml:"tun,omitempty"`
	DNS           RawDNS                    `yaml:"dns,omitempty" json:"dns"`
	TuicServer    RawTuicServer             `yaml:"tuic-server,omitempty"`
	EBpf          EBpf                      `yaml:"ebpf,omitempty"`
	IPTables      IPTables                  `yaml:"iptables,omitempty"`
	Experimental  Experimental              `yaml:"experimental,omitempty"`
	ProxyProvider map[string]map[string]any `yaml:"proxy-providers,omitempty"`
	RuleProviders map[string]RuleProvider   `yaml:"rule-providers,omitempty"`
	Proxies       []Proxy                   `yaml:"proxies,omitempty"`
	ProxyGroups   []ProxyGroup              `yaml:"proxy-groups,omitempty"`
	Rules         []string                  `yaml:"rules,omitempty"`
	SubRules      map[string][]string       `yaml:"sub-rules,omitempty"`
	Listeners     []map[string]any          `yaml:"listeners,omitempty"`

	ClashForAndroid RawClashForAndroid `yaml:"clash-for-android,omitempty" json:"clash-for-android"`
}

type RawClashForAndroid struct {
	AppendSystemDNS   bool   `yaml:"append-system-dns,omitempty" json:"append-system-dns"`
	UiSubtitlePattern string `yaml:"ui-subtitle-pattern,omitempty" json:"ui-subtitle-pattern"`
}

type TLS struct {
	Certificate     string   `yaml:"certificate,omitempty"`
	PrivateKey      string   `yaml:"private-key,omitempty"`
	CustomTrustCert []string `yaml:"custom-certifactes,omitempty"`
}

type GeoXUrl struct {
	GeoIp   string `yaml:"geoip,omitempty" json:"geoip"`
	GeoSite string `yaml:"geosite,omitempty" json:"geosite"`
	Mmdb    string `yaml:"mmdb,omitempty" json:"mmdb"`
}

type Experimental struct {
	Fingerprints     []string `yaml:"fingerprints,omitempty"`
	QUICGoDisableGSO bool     `yaml:"quic-go-disable-gso,omitempty"`
	QUICGoDisableECN bool     `yaml:"quic-go-disable-ecn,omitempty"`
	IP4PEnable       bool     `yaml:"dialer-ip4p-convert,omitempty"`
}

type Profile struct {
	StoreSelected bool `yaml:"store-selected,omitempty"`
	StoreFakeIP   bool `yaml:"store-fake-ip,omitempty"`
}

type IPTables struct {
	Enable           bool     `yaml:"enable,omitempty" json:"enable"`
	InboundInterface string   `yaml:"inbound-interface,omitempty" json:"inbound-interface"`
	Bypass           []string `yaml:"bypass,omitempty" json:"bypass"`
	DnsRedirect      bool     `yaml:"dns-redirect,omitempty" json:"dns-redirect"`
}

// EBpf config
type EBpf struct {
	RedirectToTun []string `yaml:"redirect-to-tun,omitempty" json:"redirect-to-tun"`
	AutoRedir     []string `yaml:"auto-redir,omitempty" json:"auto-redir"`
}

type RawSniffer struct {
	Enable          bool                         `yaml:"enable,omitempty" json:"enable"`
	OverrideDest    bool                         `yaml:"override-destination,omitempty" json:"override-destination"`
	Sniffing        []string                     `yaml:"sniffing,omitempty" json:"sniffing"`
	ForceDomain     []string                     `yaml:"force-domain,omitempty" json:"force-domain"`
	SkipDomain      []string                     `yaml:"skip-domain,omitempty" json:"skip-domain"`
	Ports           []string                     `yaml:"port-whitelist,omitempty" json:"port-whitelist"`
	ForceDnsMapping bool                         `yaml:"force-dns-mapping,omitempty" json:"force-dns-mapping"`
	ParsePureIp     bool                         `yaml:"parse-pure-ip,omitempty" json:"parse-pure-ip"`
	Sniff           map[string]RawSniffingConfig `yaml:"sniff,omitempty" json:"sniff"`
}

type RawSniffingConfig struct {
	Ports        []string `yaml:"ports,omitempty" json:"ports"`
	OverrideDest *bool    `yaml:"override-destination,omitempty" json:"override-destination"`
}

type RawNTP struct {
	Enable        bool   `yaml:"enable,omitempty"`
	Server        string `yaml:"server,omitempty"`
	ServerPort    int    `yaml:"server-port,omitempty"`
	Interval      int    `yaml:"interval,omitempty"`
	DialerProxy   string `yaml:"dialer-proxy,omitempty"`
	WriteToSystem bool   `yaml:"write-to-system,omitempty"`
}

type RawDNS struct {
	Enable            bool              `yaml:"enable,omitempty" json:"enable"`
	PreferH3          bool              `yaml:"prefer-h3,omitempty" json:"prefer-h3"`
	IPv6              bool              `yaml:"ipv6,omitempty" json:"ipv6"`
	IPv6Timeout       uint              `yaml:"ipv6-timeout,omitempty" json:"ipv6-timeout"`
	UseHosts          bool              `yaml:"use-hosts,omitempty" json:"use-hosts"`
	NameServer        []string          `yaml:"nameserver,omitempty" json:"nameserver"`
	Fallback          []string          `yaml:"fallback,omitempty" json:"fallback"`
	FallbackFilter    RawFallbackFilter `yaml:"fallback-filter,omitempty" json:"fallback-filter"`
	Listen            string            `yaml:"listen,omitempty" json:"listen"`
	EnhancedMode      string            `yaml:"enhanced-mode,omitempty" json:"enhanced-mode"`
	FakeIPRange       string            `yaml:"fake-ip-range,omitempty" json:"fake-ip-range"`
	FakeIPFilter      []string          `yaml:"fake-ip-filter,omitempty" json:"fake-ip-filter"`
	DefaultNameserver []string          `yaml:"default-nameserver,omitempty" json:"default-nameserver"`
	CacheAlgorithm    string            `yaml:"cache-algorithm,omitempty" json:"cache-algorithm"`
	//NameServerPolicy      *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy,omitempty" json:"nameserver-policy"`
	ProxyServerNameserver []string `yaml:"proxy-server-nameserver,omitempty" json:"proxy-server-nameserver"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip,omitempty" json:"geoip"`
	GeoIPCode string   `yaml:"geoip-code,omitempty" json:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr,omitempty" json:"ipcidr"`
	Domain    []string `yaml:"domain,omitempty" json:"domain"`
	GeoSite   []string `yaml:"geosite,omitempty" json:"geosite"`
}

type RawTun struct {
	Enable              bool     `yaml:"enable,omitempty" json:"enable"`
	Stack               string   `yaml:"stack,omitempty" json:"stack"`
	AutoRoute           bool     `yaml:"auto-route,omitempty" json:"auto-route"`
	AutoDetectInterface bool     `yaml:"auto-detect-interface,omitempty"`
	RedirectToTun       []string `yaml:"-,omitempty" json:"-"`
	DNSHijack           []string `yaml:"dns-hijack,omitempty" json:"dns-hijack"`
	Device              string   `yaml:"device,omitempty" json:"device"`
	MTU        uint32 `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	GSO        bool   `yaml:"gso,omitempty" json:"gso,omitempty"`
	GSOMaxSize uint32 `yaml:"gso-max-size,omitempty" json:"gso-max-size,omitempty"`
	//Inet4Address           []netip.Prefix `yaml:"inet4-address,omitempty" json:"inet4_address,omitempty"`
	Inet6Address             []uint32 `yaml:"inet6-address,omitempty" json:"inet6_address,omitempty"`
	StrictRoute              bool     `yaml:"strict-route,omitempty" json:"strict_route,omitempty"`
	Inet4RouteAddress        []uint32 `yaml:"inet4-route-address,omitempty" json:"inet4_route_address,omitempty"`
	Inet6RouteAddress        []uint32 `yaml:"inet6-route-address,omitempty" json:"inet6_route_address,omitempty"`
	Inet4RouteExcludeAddress []uint32 `yaml:"inet4-route-exclude-address,omitempty" json:"inet4_route_exclude_address,omitempty"`
	Inet6RouteExcludeAddress []uint32 `yaml:"inet6-route-exclude-address,omitempty" json:"inet6_route_exclude_address,omitempty"`
	IncludeInterface         []string `yaml:"include-interface,omitempty" json:"include-interface,omitempty"`
	ExcludeInterface         []string `yaml:"exclude-interface,omitempty" json:"exclude-interface,omitempty"`
	IncludeUID               []uint32 `yaml:"include-uid,omitempty" json:"include_uid,omitempty"`
	IncludeUIDRange          []string `yaml:"include-uid-range,omitempty" json:"include_uid_range,omitempty"`
	ExcludeUID               []uint32 `yaml:"exclude-uid,omitempty" json:"exclude_uid,omitempty"`
	ExcludeUIDRange          []string `yaml:"exclude-uid-range,omitempty" json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser       []int    `yaml:"include-android-user,omitempty" json:"include_android_user,omitempty"`
	IncludePackage           []string `yaml:"include-package,omitempty" json:"include_package,omitempty"`
	ExcludePackage           []string `yaml:"exclude-package,omitempty" json:"exclude_package,omitempty"`
	EndpointIndependentNat   bool     `yaml:"endpoint-independent-nat,omitempty" json:"endpoint_independent_nat,omitempty"`
	UDPTimeout               int64    `yaml:"udp-timeout,omitempty" json:"udp_timeout,omitempty"`
	FileDescriptor           int      `yaml:"file-descriptor,omitempty" json:"file-descriptor"`
}

type RawTuicServer struct {
	Enable                bool              `yaml:"enable,omitempty" json:"enable"`
	Listen                string            `yaml:"listen,omitempty" json:"listen"`
	Token                 []string          `yaml:"token,omitempty" json:"token"`
	Users                 map[string]string `yaml:"users,omitempty" json:"users,omitempty"`
	Certificate           string            `yaml:"certificate,omitempty" json:"certificate"`
	PrivateKey            string            `yaml:"private-key,omitempty" json:"private-key"`
	CongestionController  string            `yaml:"congestion-controller,omitempty" json:"congestion-controller,omitempty"`
	MaxIdleTime           int               `yaml:"max-idle-time,omitempty" json:"max-idle-time,omitempty"`
	AuthenticationTimeout int               `yaml:"authentication-timeout,omitempty" json:"authentication-timeout,omitempty"`
	ALPN                  []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	MaxUdpRelayPacketSize int               `yaml:"max-udp-relay-packet-size,omitempty" json:"max-udp-relay-packet-size,omitempty"`
	CWND                  int               `yaml:"cwnd,omitempty" json:"cwnd,omitempty"`
}
