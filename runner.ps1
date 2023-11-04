# Get data and diff
$oldJson = Get-Content -Raw -Path data.json | ConvertFrom-Json
$newJson = Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json | ConvertFrom-Json
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
            "text" = "\nCompany: $($Item.InputObject.post_title)" +
                "\nRansom Group: $($Item.InputObject.group_name)" +
                "\nDiscovered: $($Item.InputObject.discovered)"
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
    $newJson | Out-File data.json -Force
    git config --global user.name 'github-actions[bot]'
    git config --global user.email 'github-actions[bot]@users.noreply.github.com'
    git commit -am "data.json update"
    git push
}
