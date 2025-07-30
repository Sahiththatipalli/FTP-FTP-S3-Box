# deploy-lambda.ps1
# Deploy code to AWS Lambda with interactive profile selection and safe zipping

Write-Host "Fetching AWS CLI profiles..."
$profiles = aws configure list-profiles 2>$null
if (-not $profiles -or $profiles.Count -eq 0) {
    Write-Error "No AWS CLI profiles found. Please run 'aws configure sso' or 'aws configure' first."
    exit 1
}

# Show list for selection
Write-Host "`nAvailable AWS CLI profiles:"
for ($i=0; $i -lt $profiles.Count; $i++) {
    Write-Host "$($i+1)): $($profiles[$i])"
}

do {
    $profileIndex = Read-Host "Enter the number for your desired AWS CLI profile"
} while (-not ($profileIndex -as [int]) -or $profileIndex -lt 1 -or $profileIndex -gt $profiles.Count)

$awsProfile = $profiles[$profileIndex - 1].Trim()
Write-Host "`nUsing AWS CLI profile: $awsProfile"

$FunctionName = Read-Host "Enter Lambda function name"
$SourcePath = Read-Host "Enter path to your Lambda source code folder (default: .)"
if (-not $SourcePath) { $SourcePath = "." }

# Make unique zip name for this run
$zipGuid = [guid]::NewGuid().ToString().Substring(0, 8)
$zipName = "$FunctionName-deploy-$zipGuid.zip"
$tempFolder = [System.IO.Path]::GetTempPath()
$zipFullPath = Join-Path $tempFolder $zipName

# Clean up previous zip files for this function (optional)
Get-ChildItem "$tempFolder\$FunctionName-deploy-*.zip" | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "`nRefreshing AWS SSO session (if needed)..."
aws sso login --profile $awsProfile

Write-Host "`nZipping code from $SourcePath ..."
if (Test-Path $zipFullPath) { Remove-Item $zipFullPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $zipFullPath)

Write-Host "`nUploading code to Lambda function: $FunctionName ..."
try {
    $updateResult = aws lambda update-function-code --function-name $FunctionName --zip-file fileb://$zipFullPath --profile $awsProfile
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nLambda function '$FunctionName' updated successfully!"
    } else {
        Write-Error "Lambda update failed. Check the error above."
    }
} catch {
    Write-Error "Error uploading code to Lambda: $_"
}

Write-Host "`nDeployment complete. Zip file: $zipName"
