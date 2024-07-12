# Information to configure on https://console.cloud.google.com/ --> Client ID for Web application :
$clientId = "" # OAuth 2.0 Client ID
$clientSecret = "" # OAuth 2.0 Client Secret
$redirecturi = "" # OAuth 2.0 Authorized redirect URIs
$uri = "https://accounts.google.com/o/oauth2/v2/auth?scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fphotoslibrary.readonly&access_type=offline&include_granted_scopes=true&response_type=code&state=state_parameter_passthrough_value&redirect_uri=$redirecturi&client_id=$clientid"
# The return code in the return url after showing your credentials with your Google account at the previous url $uri :) :
$code = ""
$filepath = "C:\temp\Backup_Google_Photos" # Example of a directory for storing your downloading images/videos

# Creating the code query
$param = @{
    Uri         = "https://oauth2.googleapis.com/token"
    Method      = "Post"
    ContentType = "application/x-www-form-urlencoded"
    body = @{
        "code" ="$code";
        "client_id"="$clientId";
        "client_secret"="$clientSecret";
        "redirect_uri"="$redirecturi";
        "grant_type"="authorization_code"
    }
}
$token = Invoke-RestMethod @param

# Generation of the authentication headers
$headers = @{"Authorization" = "Bearer $($token.access_token)"}
# Store the refresh_token
$refreshToken = $token.refresh_token

# Fonction for creating a new token with the refreshToken
function Refresh-AccessToken {
    param (
        [string]$clientId,
        [string]$clientSecret,
        [string]$refreshToken
    )
    $body = @{
        client_id = $clientId
        client_secret = $clientSecret
        refresh_token = $refreshToken
        grant_type = 'refresh_token'
    }
    $response = Invoke-RestMethod -Uri 'https://oauth2.googleapis.com/token' -Method Post -ContentType 'application/x-www-form-urlencoded' -Body $body
    if ($response.access_token) {
        return $response
    } else {
        throw "Failed to refresh access token: $($response | ConvertTo-Json)"
    }
}

$url = 'https://photoslibrary.googleapis.com/v1/mediaItems'
$pageSize = 100  # Number of items per page, can be up to 100

# Initialize the page token
$pageToken = $null

### Loop to recover all images/videos only with Powershell 5.x but take very long time ###
do {
    $queryParams = @{
        pageSize = $pageSize
    }
    if ($pageToken) {
        $queryParams.pageToken = $pageToken
    }

    # Construct the URL with the query parameters
    $queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
    $fullUrl = "$url`?$queryString"

    # Make the GET request
    $response = Invoke-RestMethod -Uri $fullUrl -Headers $headers -Method Get
    # Mise en cache de la page suivante
    $pageToken = $response.nextPageToken

    # Checks if the query was successful
    if ($response -and $response.mediaItems) {
        $mediaItems = $response.mediaItems
    } else {
        Write-Output "No more media items."
    }

    # Downloading...
    try {
        foreach ($item in $mediaItems) {
            # Retrieve image information
            $baseUrl = $item.baseUrl  # URL de base de l'image
            $filename = "$(Get-Date $item.mediaMetadata.creationTime -Format yyyy-MM-dd_hh-mm-ss).$(($item.filename -split "\.")[-1])"  # Nom du fichier
            
            # Creating the download URL based on an image or video
            if ($item.mimeType -like "video*") {
                $imageUrl = "$baseUrl=dv"
            } else {
                $imageUrl = "$baseUrl=d"
            }
            
            # Download the image using the base URL (baseUrl)
            $outputFile = "C:\temp\Backup_Google_Photos\$filename"
            Invoke-WebRequest -Uri $imageUrl -OutFile $outputFile
        }
    } catch {
        if ($error[0].Exception.Response.StatusCode.Value__ -eq 401) {
            # Token expiré, rafraîchir le token d'accès
            Write-Output "Access token expired, refreshing token..."
            $accesstoken = Refresh-AccessToken -clientId $clientId -clientSecret $clientSecret -refreshToken $refreshToken
            $headers = @{
                'Authorization' = "Bearer $($accesstoken.access_token)"
            }
            $refreshToken = $accesstoken.refresh_token
        } else {
            New-Item -Path "$filepath\error" -Name "$($error[0].Exception.Response.StatusCode.Value__)_$($filename).txt" -ItemType "file" -Value $item
        }
    }
} while ($pageToken)

### Loop to retrieve all images/videos faster than Powershell 5.x but requires Powershell 7.x ###
$batchSize = 10  # Nombre de téléchargements parallèles
do {
    $queryParams = @{
        pageSize = $pageSize
    }
    if ($pageToken) {
        $queryParams.pageToken = $pageToken
    }

    # Construct the URL with the query parameters
    $queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
    $fullUrl = "$url`?$queryString"

    # Make the GET request
    $response = Invoke-RestMethod -Uri $fullUrl -Headers $headers -Method Get
    # Caching the next page
    $pageToken = $response.nextPageToken

    # Checks if the query was successful
    if ($response -and $response.mediaItems) {
        $mediaItems = $response.mediaItems
    } else {
        Write-Output "No more media items."
    }

    # Downloading...
    try {
        $mediaItems | ForEach-Object -ThrottleLimit $batchSize -Parallel {
            $baseUrl = $_.baseUrl  # URL de base de l'image
            $filename = "$(Get-Date $_.mediaMetadata.creationTime -Format yyyy-MM-dd_hh-mm-ss).$(($_.filename -split "\.")[-1])"  # Nom du fichier
            
            # Creating the download URL based on an image or video
            if ($_.mimeType -like "video*") {
                $imageUrl = "$baseUrl=dv"
            } else {
                $imageUrl = "$baseUrl=d"
            }
            
            # Download the image using the base URL (baseUrl)
            $outputFile = "$FilePath\$filename"
            Invoke-WebRequest -Uri $imageUrl -OutFile $outputFile
        }
    } catch {
        if ($error[0].Exception.Response.StatusCode.Value__ -eq 401) {
            # Token expiré, rafraîchir le token d'accès
            Write-Output "Access token expired, refreshing token..."
            $accesstoken = Refresh-AccessToken -clientId $clientId -clientSecret $clientSecret -refreshToken $refreshToken
            $headers = @{
                'Authorization' = "Bearer $($accesstoken.access_token)"
            }
            $refreshToken = $accesstoken.refresh_token
        } else {
            New-Item -Path "$filepath\error" -Name "$($error[0].Exception.Response.StatusCode.Value__)_$($filename).txt" -ItemType "file" -Value $item
        }
    }
} while ($pageToken)
