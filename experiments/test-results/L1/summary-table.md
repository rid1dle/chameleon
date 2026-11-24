| client | http | ja4 | akamai_h2 | first_stream |
|---|---|---|---|---|
| `cfprobe-default` | `h2` | `t13d1711h2_5b57614c22b0_8af51f2a06eb` | `2:0;4:2097152;5:16384;6:16384\|5177345\|0\|m,s,a,p` | `1` |
| `chromium-headful` | `h2` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `1` |
| `chromium124-headless` | `h2` | `t13d1516h2_8daaf6152771_02713d6af862` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `1` |
| `chromium152-headless` | `h2` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `1` |
| `ci-chrome152` | `h2` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `1` |
| `ci-firefox155` | `h2` | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | `1` |
| `curl-host` | `h2` | `t13d3013h2_1d37bd780c83_8537cf56674e` | `3:100;4:65536;2:0\|1048510465\|0\|m,s,a,p` | `1` |
| `flaresolverr-chrome` | `h2` | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `1` |
| `okhttp-suwayomi` | `h2` | `t13d1114h2_5e2a75874763_89e9e4bb3419` | `4:16777216\|16711681\|0\|m,p,a,s` | `3` |

## Header order (pseudo-headers excluded) and User-Agent

- **cfprobe-default**: `user-agent,accept`  
  UA: `cfprobe/0.1.0`
- **chromium-headful**: `sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority`  
  UA: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36`
- **chromium124-headless**: `sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority`  
  UA: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36`
- **chromium152-headless**: `sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority`  
  UA: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/152.0.0.0 Safari/537.36`
- **ci-chrome152**: `sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority,cache-control`  
  UA: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36`
- **ci-firefox155**: `user-agent,accept,accept-language,accept-encoding,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,priority,te`  
  UA: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0`
- **curl-host**: `user-agent,accept`  
  UA: `curl/8.22.0`
- **flaresolverr-chrome**: `sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority`  
  UA: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36`
- **okhttp-suwayomi**: `user-agent,accept-encoding`  
  UA: `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36`
