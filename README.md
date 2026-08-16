# custom-blocklist

Списки доменов и IP-подсетей для обхода геоблокировок/блокировок РКН на роутере
(OpenWrt + [splify2](https://github.com/xyzmean/splify2)). Списки обновляются автоматически раз в день через GitHub
Actions, руками подсети почти никогда не трогаю.

## Что внутри

```
lists/
  <сервис>_domains.lst   - домены сервиса (правится руками)
  <сервис>_ip.lst        - IP-подсети сервиса (генерируются скриптом)
update_lists.py           - генератор, обновляет *_ip.lst из живых источников
requirements.txt
.github/workflows/        - автозапуск генератора по расписанию
```

Поддерживаемые сервисы: Telegram, YouTube, Gemini, Claude, DeepL, Discord,
SoundCloud, GitHub, Steam (Valve), Cloudflare CDN, CloudFront CDN. TikTok в списке
есть, но не обновляется автоматически: надёжного источника под него пока не
нашёл, IP-подсети там правятся руками.

## Как это использовать

Файлы `lists/*.lst`, это обычные списки CIDR/доменов, по одной записи на
строку, готовые для импорта в splify2 (или любую другую систему
policy-routing на OpenWrt, которая ест такой формат).

## Откуда берутся IP-адреса

Каждый сервис в `update_lists.py` описан рецептом:

| Источник | Что делает |
|---|---|
| **resolve** | резолвит домены из `*_domains.lst` через 4 публичных DNS параллельно, берёт /24 вокруг каждого ответа |
| **asn** | тянет все анонсируемые подсети ASN-провайдера (RIPEstat, потом ip.guide, потом bgpview, первый живой источник побеждает) |
| **cloudflare / cloudfront** | официальные фиды этих CDN |
| **github_meta** | официальный список IP GitHub (`api.github.com/meta`), берёт все категории сразу (web, api, git, actions, pages и т.д.) |
| **official_url** | готовый список от самого сервиса, например Telegram публикует свой `cidr.txt` |

Результат схлопывается, дедуплицируется, и из него вырезаются адреса самих
DNS-резолверов (1.1.1.1, 8.8.8.8 и т.д.), чтобы список случайно не увёл в
туннель собственный DNS.

## Автообновление

`.github/workflows/update-lists.yml` запускает генератор раз в день (крон в
самом файле) и коммитит изменения, если что-то поменялось. Прогресс и логи,
во вкладке **Actions** репозитория. Запустить вручную можно там же кнопкой
**Run workflow**.

## Запуск руками

```bash
pip install -r requirements.txt

python3 update_lists.py --list              # какой сервис из чего собирается
python3 update_lists.py --dry-run            # что изменится, без записи
python3 update_lists.py                      # обновить всё
python3 update_lists.py --only telegram,youtube
```

## Добавить новый сервис

В `update_lists.py`, в словарь `SERVICES`, новая запись:

```python
"myservice": Service(
    ip_file="myservice_ip.lst",
    domains_file="myservice_domains.lst",   # опционально
    sources=[Source("resolve"), Source("asn", asn=12345)],
),
```

Файлы на диске создавать не нужно, скрипт напишет их сам при первом запуске.
