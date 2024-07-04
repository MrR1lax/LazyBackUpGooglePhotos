# Information configure sur https://console.cloud.google.com/ --> Client ID for Web application :
$clientId = "" # OAuth 2.0 Client ID
$clientSecret = "" # OAuth 2.0 Client Secret
$redirecturi = "http://localhost" # OAuth 2.0 Authorized redirect URIs
$uri = "https://accounts.google.com/o/oauth2/v2/auth?scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fphotoslibrary.readonly&access_type=offline&include_granted_scopes=true&response_type=code&state=state_parameter_passthrough_value&redirect_uri=$redirecturi&client_id=$clientid"
# Le code de retour dans l'url de retour apres avoir montrer patte blanche avec son compte Google à la precedente url $uri :) :
$code = ""

# creation de la requete de code :) :
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

# generation du Headers d'authentification :
$headers = @{"Authorization" = "Bearer $($token.access_token)"}
# On stock le refreshtoken :
$refreshToken = $token.refresh_token

# On prepare la fonction de refreshToken :
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

<# Good :) il fallait bien debuter quelque part :) :
$uri = "https://photoslibrary.googleapis.com/v1/mediaItems"
$result = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
#>

$url = 'https://photoslibrary.googleapis.com/v1/mediaItems'
$pageSize = 100  # Nombre d'éléments par page, peut aller jusqu'à 100

# Initialiser le token de page
$pageToken = $null

# Boucle pour récupérer toutes les pages Powershell 5.1
do {
    $queryParams = @{
        pageSize = $pageSize
    }
    if ($pageToken) {
        $queryParams.pageToken = $pageToken
    }

    # Construire l'URL avec les paramètres de requête
    $queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
    $fullUrl = "$url`?$queryString"

    # Effectuer la requête GET
    $response = Invoke-RestMethod -Uri $fullUrl -Headers $headers -Method Get
    # Mise en cache de la page suivante
    $pageToken = $response.nextPageToken

    # Vérifiez si la requête a réussi
    if ($response -and $response.mediaItems) {
        $mediaItems = $response.mediaItems
    } else {
        Write-Output "No more media items."
    }

    # Téléchargement...
    try {
        foreach ($item in $mediaItems) {
            # Récupérer les informations sur l'image
            $baseUrl = $item.baseUrl  # URL de base de l'image
            $filename = "$(Get-Date $item.mediaMetadata.creationTime -Format yyyy-MM-dd_hh-mm-ss).$(($item.filename -split "\.")[-1])"  # Nom du fichier
            
            # URL de téléchargement en fonction d'une image ou d'une vidéo :
            if ($item.mimeType -like "video*") {
                $imageUrl = "$baseUrl=dv"
            } else {
                $imageUrl = "$baseUrl=d"
            }
            
            # Télécharger l'image en utilisant l'URL de base (baseUrl)
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
            New-Item -Path "C:\temp\Backup_Google_Photos\error" -Name "$($error[0].Exception.Response.StatusCode.Value__)_$($filename).txt" -ItemType "file" -Value $item
        }
    }
} while ($pageToken)

# Boucle pour récupérer toutes les pages Powershell 7.4
$batchSize = 10  # Nombre de téléchargements parallèles
do {
    $queryParams = @{
        pageSize = $pageSize
    }
    if ($pageToken) {
        $queryParams.pageToken = $pageToken
    }

    # Construire l'URL avec les paramètres de requête
    $queryString = ($queryParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
    $fullUrl = "$url`?$queryString"

    # Effectuer la requête GET
    $response = Invoke-RestMethod -Uri $fullUrl -Headers $headers -Method Get
    # Mise en cache de la page suivante
    $pageToken = $response.nextPageToken

    # Vérifiez si la requête a réussi
    if ($response -and $response.mediaItems) {
        $mediaItems = $response.mediaItems
    } else {
        Write-Output "No more media items."
    }

    # Téléchargement...
    try {
        $mediaItems | ForEach-Object -ThrottleLimit $batchSize -Parallel {
            $baseUrl = $_.baseUrl  # URL de base de l'image
            $filename = "$(Get-Date $_.mediaMetadata.creationTime -Format yyyy-MM-dd_hh-mm-ss).$(($_.filename -split "\.")[-1])"  # Nom du fichier
            
            # URL de téléchargement en fonction d'une image ou d'une vidéo :
            if ($_.mimeType -like "video*") {
                $imageUrl = "$baseUrl=dv"
            } else {
                $imageUrl = "$baseUrl=d"
            }
            
            # Télécharger l'image en utilisant l'URL de base (baseUrl)
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
            New-Item -Path "C:\temp\Backup_Google_Photos\error" -Name "$($error[0].Exception.Response.StatusCode.Value__)_$($filename).txt" -ItemType "file" -Value $item
        }
    }
} while ($pageToken)