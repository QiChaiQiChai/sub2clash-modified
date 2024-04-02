package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sub2clash/logger"
	"sub2clash/model"
	"sub2clash/parser"
	"sub2clash/utils"
	"sub2clash/validator"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func BuildSub(clashType model.ClashType, query validator.SubValidator, template string) (
	*model.Subscription, error,
) {
	// 定义变量
	var temp = &model.Subscription{}
	var sub = &model.Subscription{}
	var err error
	var templateBytes []byte
	// 加载模板
	if query.Template != "" {
		template = query.Template
	}
	if strings.HasPrefix(template, "http") {
		templateBytes, err = utils.LoadSubscription(template, query.Refresh)
		if err != nil {
			logger.Logger.Debug(
				"load template failed", zap.String("template", template), zap.Error(err),
			)
			return nil, errors.New("加载模板失败: " + err.Error())
		}
	} else {
		unescape, err := url.QueryUnescape(template)
		if err != nil {
			return nil, errors.New("加载模板失败: " + err.Error())
		}
		templateBytes, err = utils.LoadTemplate(unescape)
		if err != nil {
			logger.Logger.Debug(
				"load template failed", zap.String("template", template), zap.Error(err),
			)
			return nil, errors.New("加载模板失败: " + err.Error())
		}
	}
	// 解析模板
	err = yaml.Unmarshal(templateBytes, &temp)
	if err != nil {
		logger.Logger.Debug("parse template failed", zap.Error(err))
		return nil, errors.New("解析模板失败: " + err.Error())
	}
	var proxyList []model.Proxy
	// 加载订阅
	for i := range query.Subs {
		data, err := utils.LoadSubscription(query.Subs[i], query.Refresh)
		subName := ""
		if strings.Contains(query.Subs[i], "#") {
			subName = query.Subs[i][strings.LastIndex(query.Subs[i], "#")+1:]
		}
		if err != nil {
			logger.Logger.Debug(
				"load subscription failed", zap.String("url", query.Subs[i]), zap.Error(err),
			)
			return nil, errors.New("加载订阅失败: " + err.Error())
		}
		// 解析订阅
		err = yaml.Unmarshal(data, &sub)
		var newProxies []model.Proxy
		if err != nil {
			reg, _ := regexp.Compile("(ssr|ss|vmess|trojan|vless|hysteria)://")
			if reg.Match(data) {
				p := utils.ParseProxy(strings.Split(string(data), "\n")...)
				newProxies = p
			} else {
				// 如果无法直接解析，尝试Base64解码
				base64, err := parser.DecodeBase64(string(data))
				if err != nil {
					logger.Logger.Debug(
						"parse subscription failed", zap.String("url", query.Subs[i]),
						zap.String("data", string(data)),
						zap.Error(err),
					)
					return nil, errors.New("加载订阅失败: " + err.Error())
				}
				p := utils.ParseProxy(strings.Split(base64, "\n")...)
				newProxies = p
			}
		} else {
			newProxies = sub.Proxies
		}
		if subName != "" {
			for i := range newProxies {
				newProxies[i].SubName = subName
			}
		}
		proxyList = append(proxyList, newProxies...)
	}
	// 添加自定义节点
	if len(query.Proxies) != 0 {
		proxyList = append(proxyList, utils.ParseProxy(query.Proxies...)...)
	}
	// 给节点添加订阅名称
	for i := range proxyList {
		if proxyList[i].SubName != "" {
			proxyList[i].Name = strings.TrimSpace(proxyList[i].SubName) + " " + strings.TrimSpace(proxyList[i].Name)
		}
	}
	// 删除节点
	if strings.TrimSpace(query.Remove) != "" {
		newProxyList := make([]model.Proxy, 0, len(proxyList))
		for i := range proxyList {
			removeReg, err := regexp.Compile(query.Remove)
			if err != nil {
				logger.Logger.Debug("remove regexp compile failed", zap.Error(err))
				return nil, errors.New("remove 参数非法: " + err.Error())
			}
			// 删除匹配到的节点
			if removeReg.MatchString(proxyList[i].Name) {
				continue // 如果匹配到要删除的元素，跳过该元素，不添加到新切片中
			}
			newProxyList = append(newProxyList, proxyList[i]) // 将要保留的元素添加到新切片中
		}
		proxyList = newProxyList
	}
	// 重命名
	if len(query.ReplaceKeys) != 0 {
		// 创建重命名正则表达式
		replaceRegs := make([]*regexp.Regexp, 0, len(query.ReplaceKeys))
		for _, v := range query.ReplaceKeys {
			replaceReg, err := regexp.Compile(v)
			if err != nil {
				logger.Logger.Debug("replace regexp compile failed", zap.Error(err))
				return nil, errors.New("replace 参数非法: " + err.Error())
			}
			replaceRegs = append(replaceRegs, replaceReg)
		}
		for i := range proxyList {
			// 重命名匹配到的节点
			for j, v := range replaceRegs {
				if v.MatchString(proxyList[i].Name) {
					proxyList[i].Name = v.ReplaceAllString(
						proxyList[i].Name, query.ReplaceTo[j],
					)
				}
			}
		}
	}
	// 定义国家/地区的 emoji 正则表达式映射
	var CountryEmojiRegexMap = []struct {
		Emoji string
		Regex *regexp.Regexp
	}{
		{Emoji: "🇭🇰", Regex: regexp.MustCompile("香港|沪港|呼港|中港|HKT|HKBN|HGC|WTT|CMI|穗港|广港|京港|🇭🇰|HK|Hongkong|Hong Kong|HongKong|HONG KONG")},
		{Emoji: "🇹🇼", Regex: regexp.MustCompile("台湾|台灣|臺灣|台北|台中|新北|彰化|台|CHT|HINET|TW|Taiwan|TAIWAN")},
		{Emoji: "🇲🇴", Regex: regexp.MustCompile("澳门|澳門|CTM|MAC|Macao|Macau")},
		{Emoji: "🇸🇬", Regex: regexp.MustCompile("新加坡|狮城|獅城|沪新|京新|泉新|穗新|深新|杭新|广新|廣新|滬新|SG|Singapore|SINGAPORE")},
		{Emoji: "🇯🇵", Regex: regexp.MustCompile("日本|东京|大阪|埼玉|京日|苏日|沪日|广日|上日|穗日|川日|中日|泉日|杭日|深日|JP|Japan|JAPAN")},
		{Emoji: "🇺🇸", Regex: regexp.MustCompile("美国|美國|京美|硅谷|凤凰城|洛杉矶|西雅图|圣何塞|芝加哥|哥伦布|纽约|广美|USA|America|United States")},
		{Emoji: "🇰🇷", Regex: regexp.MustCompile("韩国|韓國|首尔|韩|韓|春川|KOR|KR|Kr|Korea")},
		{Emoji: "🇰🇵", Regex: regexp.MustCompile("朝鲜|KP|North Korea")},
		{Emoji: "🇷🇺", Regex: regexp.MustCompile("俄罗斯|俄羅斯|毛子|俄国|RU|RUS|Russia")},
		{Emoji: "🇮🇳", Regex: regexp.MustCompile("印度|孟买|IND|India|INDIA|Mumbai")},
		{Emoji: "🇮🇩", Regex: regexp.MustCompile("印尼|印度尼西亚|雅加达|ID|IDN|Indonesia")},
		{Emoji: "🇬🇧", Regex: regexp.MustCompile("英国|英國|伦敦|UK|England|United Kingdom|Britain")},
		{Emoji: "🇩🇪", Regex: regexp.MustCompile("德国|德國|法兰克福|🇩🇪|German|GERMAN")},
		{Emoji: "🇫🇷", Regex: regexp.MustCompile("法国|法國|巴黎|France")},
		{Emoji: "🇩🇰", Regex: regexp.MustCompile("丹麦|丹麥|DK|DNK|Denmark")},
		{Emoji: "🇳🇴", Regex: regexp.MustCompile("挪威|Norway")},
		{Emoji: "🇮🇹", Regex: regexp.MustCompile("意大利|義大利|米兰|Italy|Nachash")},
		{Emoji: "🇻🇦", Regex: regexp.MustCompile("梵蒂冈|梵蒂岡|Vatican City")},
		{Emoji: "🇧🇪", Regex: regexp.MustCompile("比利时|比利時|Belgium")},
		{Emoji: "🇦🇺", Regex: regexp.MustCompile("澳大利亚|澳洲|墨尔本|悉尼|Australia|Sydney")},
		{Emoji: "🇨🇦", Regex: regexp.MustCompile("加拿大|蒙特利尔|温哥华|多伦多|滑铁卢|楓葉|枫叶|CA|CAN|Waterloo|Canada|CANADA")},
		{Emoji: "🇲🇾", Regex: regexp.MustCompile("马来西亚|马来|馬來|MY|Malaysia|MALAYSIA")},
		{Emoji: "🇲🇻", Regex: regexp.MustCompile("马尔代夫|馬爾代夫|Maldives")},
		{Emoji: "🇹🇷", Regex: regexp.MustCompile("土耳其|伊斯坦布尔|TR_|TUR|Turkey")},
		{Emoji: "🇵🇭", Regex: regexp.MustCompile("菲律宾|菲律賓|Philippines")},
		{Emoji: "🇹🇭", Regex: regexp.MustCompile("泰国|泰國|曼谷|Thailand")},
		{Emoji: "🇻🇳", Regex: regexp.MustCompile("越南|胡志明市|Vietnam")},
		{Emoji: "🇰🇭", Regex: regexp.MustCompile("柬埔寨|Cambodia")},
		{Emoji: "🇱🇦", Regex: regexp.MustCompile("老挝|Laos")},
		{Emoji: "🇧🇩", Regex: regexp.MustCompile("孟加拉|Bengal")},
		{Emoji: "🇲🇲", Regex: regexp.MustCompile("缅甸|緬甸|Myanmar")},
		{Emoji: "🇱🇧", Regex: regexp.MustCompile("黎巴嫩|Lebanon")},
		{Emoji: "🇺🇦", Regex: regexp.MustCompile("乌克兰|烏克蘭|Ukraine")},
		{Emoji: "🇭🇺", Regex: regexp.MustCompile("匈牙利|Hungary")},
		{Emoji: "🇨🇭", Regex: regexp.MustCompile("瑞士|苏黎世|Switzerland")},
		{Emoji: "🇸🇪", Regex: regexp.MustCompile("瑞典|SE|Sweden")},
		{Emoji: "🇱🇺", Regex: regexp.MustCompile("卢森堡|Luxembourg")},
		{Emoji: "🇦🇹", Regex: regexp.MustCompile("奥地利|奧地利|维也纳|Austria")},
		{Emoji: "🇨🇿", Regex: regexp.MustCompile("捷克|Czechia")},
		{Emoji: "🇬🇷", Regex: regexp.MustCompile("希腊|希臘|Greece")},
		{Emoji: "🇮🇸", Regex: regexp.MustCompile("冰岛|冰島|ISL|Iceland")},
		{Emoji: "🇳🇿", Regex: regexp.MustCompile("新西兰|新西蘭|New Zealand")},
		{Emoji: "🇮🇪", Regex: regexp.MustCompile("爱尔兰|愛爾蘭|都柏林Ireland|IRELAND")},
		{Emoji: "🇮🇲", Regex: regexp.MustCompile("马恩岛|馬恩島|Mannin|Isle of Man")},
		{Emoji: "🇱🇹", Regex: regexp.MustCompile("立陶宛|Lithuania")},
		{Emoji: "🇫🇮", Regex: regexp.MustCompile("芬兰|芬蘭|赫尔辛基|Finland")},
		{Emoji: "🇦🇷", Regex: regexp.MustCompile("阿根廷|Argentina")},
		{Emoji: "🇺🇾", Regex: regexp.MustCompile("乌拉圭|烏拉圭|Uruguay")},
		{Emoji: "🇵🇾", Regex: regexp.MustCompile("巴拉|Paraguay")},
		{Emoji: "🇯🇲", Regex: regexp.MustCompile("牙买加|牙買加|Jamaica")},
		{Emoji: "🇸🇷", Regex: regexp.MustCompile("苏里南|蘇里南|Suriname")},
		{Emoji: "🇨🇼", Regex: regexp.MustCompile("库拉索|庫拉索|Curaçao")},
		{Emoji: "🇨🇴", Regex: regexp.MustCompile("哥伦比亚|Colombia")},
		{Emoji: "🇪🇨", Regex: regexp.MustCompile("厄瓜多尔|Ecuador")},
		{Emoji: "🇪🇸", Regex: regexp.MustCompile("西班牙|Spain")},
		{Emoji: "🇵🇹", Regex: regexp.MustCompile("葡萄牙|Portugal")},
		{Emoji: "🇮🇱", Regex: regexp.MustCompile("以色列|Israel")},
		{Emoji: "🇸🇦", Regex: regexp.MustCompile("沙特|利雅得|吉达|Saudi|Saudi Arabia")},
		{Emoji: "🇲🇳", Regex: regexp.MustCompile("蒙古|Mongolia")},
		{Emoji: "🇦🇪", Regex: regexp.MustCompile("阿联酋|迪拜|Dubai|United Arab Emirates")},
		{Emoji: "🇦🇿", Regex: regexp.MustCompile("阿塞拜疆|Azerbaijan")},
		{Emoji: "🇦🇲", Regex: regexp.MustCompile("亚美尼亚|亞美尼|Armenia")},
		{Emoji: "🇰🇿", Regex: regexp.MustCompile("哈萨克斯坦|哈薩克斯坦|Kazakhstan")},
		{Emoji: "🇰🇬", Regex: regexp.MustCompile("吉尔吉斯坦|吉尔吉斯斯坦|Kyrghyzstan")},
		{Emoji: "🇺🇿", Regex: regexp.MustCompile("乌兹别克斯坦|烏茲別克斯坦|Uzbekistan")},
		{Emoji: "🇧🇷", Regex: regexp.MustCompile("巴西|圣保罗|维涅杜|Brazil")},
		{Emoji: "🇨🇱", Regex: regexp.MustCompile("智利|Chile|CHILE")},
		{Emoji: "🇵🇪", Regex: regexp.MustCompile("秘鲁|祕魯|Peru")},
		{Emoji: "🇨🇺", Regex: regexp.MustCompile("古巴|Cuba")},
		{Emoji: "🇧🇹", Regex: regexp.MustCompile("不丹|Bhutan")},
		{Emoji: "🇦🇩", Regex: regexp.MustCompile("安道尔|Andorra")},
		{Emoji: "🇲🇹", Regex: regexp.MustCompile("马耳他|Malta")},
		{Emoji: "🇲🇨", Regex: regexp.MustCompile("摩纳哥|摩納哥|Monaco")},
		{Emoji: "🇷🇴", Regex: regexp.MustCompile("罗马尼亚|Rumania")},
		{Emoji: "🇧🇬", Regex: regexp.MustCompile("保加利亚|保加利亞|Bulgaria")},
		{Emoji: "🇭🇷", Regex: regexp.MustCompile("克罗地亚|克羅地亞|Croatia")},
		{Emoji: "🇲🇰", Regex: regexp.MustCompile("北马其顿|北馬其頓|North Macedonia")},
		{Emoji: "🇷🇸", Regex: regexp.MustCompile("塞尔维亚|塞爾維|Seville|Sevilla")},
		{Emoji: "🇨🇾", Regex: regexp.MustCompile("塞浦路|Cyprus")},
		{Emoji: "🇱🇻", Regex: regexp.MustCompile("拉脱维亚|Latvia|Latvija")},
		{Emoji: "🇲🇩", Regex: regexp.MustCompile("摩尔多瓦|摩爾多瓦|Moldova")},
		{Emoji: "🇸🇰", Regex: regexp.MustCompile("斯洛伐克|Slovakia")},
		{Emoji: "🇪🇪", Regex: regexp.MustCompile("爱沙尼亚|Estonia")},
		{Emoji: "🇧🇾", Regex: regexp.MustCompile("白俄罗斯|白俄羅斯|White Russia|Republic of Belarus|Belarus")},
		{Emoji: "🇧🇳", Regex: regexp.MustCompile("文莱|汶萊|BRN|Negara Brunei Darussalam")},
		{Emoji: "🇬🇺", Regex: regexp.MustCompile("关岛|關島|Guam")},
		{Emoji: "🇫🇯", Regex: regexp.MustCompile("斐济|斐濟|Fiji")},
		{Emoji: "🇯🇴", Regex: regexp.MustCompile("约旦|約旦|Jordan")},
		{Emoji: "🇬🇪", Regex: regexp.MustCompile("格鲁吉亚|格魯吉亞|Georgia")},
		{Emoji: "🇬🇮", Regex: regexp.MustCompile("直布罗陀|直布羅陀|Gibraltar")},
		{Emoji: "🇸🇲", Regex: regexp.MustCompile("圣马力诺|聖馬利諾|San Marino")},
		{Emoji: "🇳🇵", Regex: regexp.MustCompile("尼泊尔|Nepal")},
		{Emoji: "🇫🇴", Regex: regexp.MustCompile("法罗群岛|法羅群島|Faroe Islands")},
		{Emoji: "🇦🇽", Regex: regexp.MustCompile("奥兰群岛|奧蘭群島|Åland")},
		{Emoji: "🇸🇮", Regex: regexp.MustCompile("斯洛文尼亚|斯洛文尼|Slovenia")},
		{Emoji: "🇦🇱", Regex: regexp.MustCompile("阿尔巴尼亚|阿爾巴尼|Albania")},
		{Emoji: "🇹🇱", Regex: regexp.MustCompile("东帝汶|東帝汶|East Timor")},
		{Emoji: "🇵🇦", Regex: regexp.MustCompile("巴拿马|巴拿馬|Panama")},
		{Emoji: "🇧🇲", Regex: regexp.MustCompile("百慕大|Bermuda")},
		{Emoji: "🇬🇱", Regex: regexp.MustCompile("格陵兰|格陵蘭|Greenland")},
		{Emoji: "🇨🇷", Regex: regexp.MustCompile("哥斯达黎加|Costa Rica")},
		{Emoji: "🇻🇬", Regex: regexp.MustCompile("英属维尔京|British Virgin Islands")},
		{Emoji: "🇻🇮", Regex: regexp.MustCompile("美属维尔京|United States Virgin Islands")},
		{Emoji: "🇲🇽", Regex: regexp.MustCompile("墨西哥|MX|MEX|MEX|MEXICO")},
		{Emoji: "🇲🇪", Regex: regexp.MustCompile("黑山|Montenegro")},
		{Emoji: "🇳🇱", Regex: regexp.MustCompile("荷兰|荷蘭|尼德蘭|阿姆斯特丹|NL|Netherlands|Amsterdam")},
		{Emoji: "🇵🇱", Regex: regexp.MustCompile("波兰|波蘭|POL|Poland")},
		{Emoji: "🇩🇿", Regex: regexp.MustCompile("阿尔及利亚|Algeria")},
		{Emoji: "🇧🇦", Regex: regexp.MustCompile("波黑共和国|波黑|Bosnia and Herzegovina")},
		{Emoji: "🇱🇮", Regex: regexp.MustCompile("列支敦士登|Liechtenstein")},
		{Emoji: "🇷🇪", Regex: regexp.MustCompile("留尼汪|留尼旺|Réunion|Reunion")},
		{Emoji: "🇿🇦", Regex: regexp.MustCompile("南非|约翰内斯堡|South Africa|Johannesburg")},
		{Emoji: "🇪🇬", Regex: regexp.MustCompile("埃及|Egypt")},
		{Emoji: "🇬🇭", Regex: regexp.MustCompile("加纳|Ghana")},
		{Emoji: "🇲🇱", Regex: regexp.MustCompile("马里|馬里|Mali")},
		{Emoji: "🇲🇦", Regex: regexp.MustCompile("摩洛哥|Morocco")},
		{Emoji: "🇹🇳", Regex: regexp.MustCompile("突尼|Tunisia")},
		{Emoji: "🇱🇾", Regex: regexp.MustCompile("利比亚|Libya")},
		{Emoji: "🇰🇪", Regex: regexp.MustCompile("肯尼亚|肯尼亞|Kenya")},
		{Emoji: "🇷🇼", Regex: regexp.MustCompile("卢旺达|盧旺達|Rwanda")},
		{Emoji: "🇨🇻", Regex: regexp.MustCompile("佛得角|維德角|Cape Verde")},
		{Emoji: "🇦🇴", Regex: regexp.MustCompile("安哥拉|Angola")},
		{Emoji: "🇳🇬", Regex: regexp.MustCompile("尼日利亚|尼日利亞|拉各斯|Nigeria")},
		{Emoji: "🇲🇺", Regex: regexp.MustCompile("毛里求斯|Mauritius")},
		{Emoji: "🇴🇲", Regex: regexp.MustCompile("阿曼|Oman")},
		{Emoji: "🇧🇭", Regex: regexp.MustCompile("巴林|Bahrain")},
		{Emoji: "🇮🇶", Regex: regexp.MustCompile("伊拉克|Iraq")},
		{Emoji: "🇮🇷", Regex: regexp.MustCompile("伊朗|Iran")},
		{Emoji: "🇦🇫", Regex: regexp.MustCompile("阿富汗|Afghanistan")},
		{Emoji: "🇵🇰", Regex: regexp.MustCompile("巴基斯坦|Pakistan|PAKISTAN")},
		{Emoji: "🇶🇦", Regex: regexp.MustCompile("卡塔尔|卡塔爾|Qatar")},
		{Emoji: "🇸🇾", Regex: regexp.MustCompile("叙利亚|敘利亞|Syria")},
		{Emoji: "🇱🇰", Regex: regexp.MustCompile("斯里兰卡|斯里蘭卡|Sri Lanka")},
		{Emoji: "🇻🇪", Regex: regexp.MustCompile("委内瑞拉|Venezuela")},
		{Emoji: "🇬🇹", Regex: regexp.MustCompile("危地马拉|Guatemala")},
		{Emoji: "🇵🇷", Regex: regexp.MustCompile("波多黎各|Puerto Rico")},
		{Emoji: "🇰🇾", Regex: regexp.MustCompile("开曼群岛|開曼群島|盖曼群岛|凯门群岛|Cayman Islands")},
		{Emoji: "🇸🇯", Regex: regexp.MustCompile("斯瓦尔巴|扬马延|Svalbard|Mayen")},
		{Emoji: "🇭🇳", Regex: regexp.MustCompile("洪都拉斯|Honduras")},
		{Emoji: "🇳🇮", Regex: regexp.MustCompile("尼加拉瓜|Nicaragua")},
		{Emoji: "🇦🇶", Regex: regexp.MustCompile("南极|南|Antarctica")},
		{Emoji: "🇨🇳", Regex: regexp.MustCompile("中国|中國|江苏|北京|上海|广州|深圳|杭州|徐州|青岛|宁波|镇江|沈阳|济南|回国|back|China")},
	}
	// 遍历代理列表，查找是否有国家地区的 emoji
	for i := range proxyList {
		hasEmoji := false
		for _, country := range CountryEmojiRegexMap {
			if strings.HasPrefix(proxyList[i].Name, country.Emoji) {
				hasEmoji = true
				break
			}
		}
		if !hasEmoji {
			for _, country := range CountryEmojiRegexMap {
				if country.Regex.MatchString(proxyList[i].Name) {
					proxyList[i].Name = country.Emoji + " " + proxyList[i].Name
					break
				}
			}
		}
	}	
	// 重名检测
	names := make(map[string]int)
	for i := range proxyList {
		if _, exist := names[proxyList[i].Name]; exist {
			names[proxyList[i].Name] = names[proxyList[i].Name] + 1
			proxyList[i].Name = proxyList[i].Name + " " + strconv.Itoa(names[proxyList[i].Name])
		} else {
			names[proxyList[i].Name] = 0
		}
	}
	// trim
	for i := range proxyList {
		proxyList[i].Name = strings.TrimSpace(proxyList[i].Name)
	}
	// 将新增节点都添加到临时变量 t 中，防止策略组排序错乱
	var t = &model.Subscription{}
	utils.AddProxy(t, query.AutoTest, query.Lazy, clashType, proxyList...)
	// 排序策略组
	switch query.Sort {
	case "sizeasc":
		sort.Sort(model.ProxyGroupsSortBySize(t.ProxyGroups))
	case "sizedesc":
		sort.Sort(sort.Reverse(model.ProxyGroupsSortBySize(t.ProxyGroups)))
	case "nameasc":
		sort.Sort(model.ProxyGroupsSortByName(t.ProxyGroups))
	case "namedesc":
		sort.Sort(sort.Reverse(model.ProxyGroupsSortByName(t.ProxyGroups)))
	default:
		sort.Sort(model.ProxyGroupsSortByName(t.ProxyGroups))
	}
	// 合并新节点和模板
	MergeSubAndTemplate(temp, t, query.IgnoreCountryGrooup)
	// 处理自定义规则
	for _, v := range query.Rules {
		if v.Prepend {
			utils.PrependRules(temp, v.Rule)
		} else {
			utils.AppendRules(temp, v.Rule)
		}
	}
	// 处理自定义 ruleProvider
	for _, v := range query.RuleProviders {
		hash := sha256.Sum224([]byte(v.Url))
		name := hex.EncodeToString(hash[:])
		provider := model.RuleProvider{
			Type:     "http",
			Behavior: v.Behavior,
			Url:      v.Url,
			Path:     "./" + name + ".yaml",
			Interval: 3600,
		}
		if v.Prepend {
			utils.PrependRuleProvider(
				temp, v.Name, v.Group, provider,
			)
		} else {
			utils.AppenddRuleProvider(
				temp, v.Name, v.Group, provider,
			)
		}
	}
	return temp, nil
}

func MergeSubAndTemplate(temp *model.Subscription, sub *model.Subscription, igcg bool) {
	// 只合并节点、策略组
	// 统计所有国家策略组名称
	var countryGroupNames []string
	for _, proxyGroup := range sub.ProxyGroups {
		if proxyGroup.IsCountryGrop {
			countryGroupNames = append(
				countryGroupNames, proxyGroup.Name,
			)
		}
	}
	var proxyNames []string
	for _, proxy := range sub.Proxies {
		proxyNames = append(proxyNames, proxy.Name)
	}
	// 将订阅中的节点添加到模板中
	temp.Proxies = append(temp.Proxies, sub.Proxies...)
	// 将订阅中的策略组添加到模板中
	for i := range temp.ProxyGroups {
		if temp.ProxyGroups[i].IsCountryGrop {
			continue
		}
		newProxies := make([]string, 0)
		countryGroupMap := make(map[string]model.ProxyGroup)
		for _, v := range sub.ProxyGroups {
			if v.IsCountryGrop {
				countryGroupMap[v.Name] = v
			}
		}
		for j := range temp.ProxyGroups[i].Proxies {
			reg := regexp.MustCompile("<(.*?)>")
			if reg.Match([]byte(temp.ProxyGroups[i].Proxies[j])) {
				key := reg.FindStringSubmatch(temp.ProxyGroups[i].Proxies[j])[1]
				switch key {
				case "all":
					newProxies = append(newProxies, proxyNames...)
				case "countries":
					newProxies = append(newProxies, countryGroupNames...)
				default:
					if len(key) == 2 {
						newProxies = append(
							newProxies, countryGroupMap[utils.GetContryName(key)].Proxies...,
						)
					}
				}
			} else {
				newProxies = append(newProxies, temp.ProxyGroups[i].Proxies[j])
			}
		}
		temp.ProxyGroups[i].Proxies = newProxies
	}
	if !igcg {
		temp.ProxyGroups = append(temp.ProxyGroups, sub.ProxyGroups...)
	}
}