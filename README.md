# kev-notifier

CISA [Known Exploited Vulnerabilities (KEV) カタログ](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)の新規追加エントリを Slack に通知する小さな Go ツール。GitHub Actions の cron で動くのでインフラ不要・無料。

## なぜ作ったか

CISA は 2025年5月12日に RSS フィードの提供を実質終了し、KEV の更新通知は GovDelivery のメール購読と SNS に移行した。RSS で KEV を追う手段が公式にはなくなったが、カタログ本体は今も JSON/CSV で公開されている。そこで:

1. 公式 JSON を定期 fetch
2. 前回実行時の CVE ID リスト（`state/seen_cves.json`、リポジトリにコミット）と diff
3. 新規エントリがあれば Slack Incoming Webhook に投稿

という素朴な仕組みで RSS の代替にした。

## セットアップ

1. **Slack Incoming Webhook を作る** — Slack App の [Incoming Webhooks](https://api.slack.com/messaging/webhooks) を有効化し、通知先チャンネルの Webhook URL を取得する。
2. **このリポジトリを GitHub に push する**。
3. **Secret を設定する** — リポジトリの Settings → Secrets and variables → Actions で `SLACK_WEBHOOK_URL` を追加。
4. おわり。`KEV check` ワークフローが6時間おきに走る。Actions タブから `workflow_dispatch` で手動実行もできる。

初回実行時は `state/seen_cves.json` が存在しないため、**通知せずに** 現在のカタログ全件（1,600件超）で state をシードする。過去分で Slack が溢れることはない。2回目以降の実行から差分だけが通知される。

## ローカルでの実行

```console
# dry-run: Slack に投げず、送信予定の payload を stdout に表示
$ go run . -dry-run

# 本番と同じ動き
$ SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... go run .

# テスト
$ go test ./...
```

フラグ:

| フラグ | デフォルト | 説明 |
|---|---|---|
| `-catalog-url` | CISA 公式 JSON | KEV カタログの取得先 |
| `-state` | `state/seen_cves.json` | 既知 CVE ID リストの保存先 |
| `-dry-run` | `false` | Slack に投稿せず stdout に出力。state も書き換えないので何度でも試せる |

## 動作の細かい話

- **state は毎回全置換** — CISA が KEV からエントリを削除した場合も state から消えるので、再追加時にちゃんと通知される。
- **Slack 投稿に失敗したら state を更新しない** — 次回実行時にリトライされる（通知の取りこぼしより重複を許容する設計）。
- **メッセージは20件ずつ分割** — Slack の 1メッセージ50ブロック制限に収まるように chunk する。
- **ランサムウェア既知悪用** (`knownRansomwareCampaignUse: Known`) のエントリには ⚠️ を付ける。

## 通知イメージ

> 🚨 **CISA KEV に 2 件追加されました**
>
> **[CVE-2026-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX)** — Vendor Product
> Vulnerability Name
> > Short description…
> 対応期限: **2026-08-01** ・ ランサムウェアでの悪用: ⚠️ **Known**
