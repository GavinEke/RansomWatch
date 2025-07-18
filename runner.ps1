# Get data and diff
$oldJson = Get-Content -Raw -Path data.json | ConvertFrom-Json
$onlineJson = Invoke-WebRequest -Uri https://raw.githubusercontent.com/GavinEke/OGransomwatch/main/posts.json
$newJson = $onlineJson | ConvertFrom-Json
$jsonDiff = Compare-Object $oldJson $newJson

if ($jsonDiff) {
    # Loop through each new entry
    ForEach ($Item in $jsonDiff) {
        # Structure Teams Message
        $JSONBody = [PSCustomObject][Ordered]@{
            "@type" = "MessageCard"
            "@context" = "<http://schema.org/extensions>"
            "summary" = "RansomWatch Alert!: $($Item.InputObject.post_title)"
            "themeColor" = '0078D7'
            "title" = "RansomWatch Alert!"
            "text" = "<pre>Company: $($Item.InputObject.post_title)" +
                "<br>Ransom Group: $($Item.InputObject.group_name)" +
                "<br>Discovered: $($Item.InputObject.discovered)</pre>"
        }
        $TeamsMessageBody = ConvertTo-Json $JSONBody

        # Post Teams Message to Webhook
        $IRMParams = @{
            "URI" = $env:TEAMS_WEBHOOK_URL
            "Method" = 'POST'
            "Body" = $TeamsMessageBody
            "ContentType" = 'application/json'
        }
        Invoke-RestMethod @IRMParams
    }

    # Override data.json with new data and git push
    $onlineJson.content | Out-File data.json -Force
    git config --global user.name 'github-actions[bot]'
    git config --global user.email 'github-actions[bot]@users.noreply.github.com'
    git commit -am "data.json update"
    git push
}
