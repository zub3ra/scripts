$scope = "User"
$pathElements = @([Environment]::GetEnvironmentVariable("Path", $scope) -split ";")
$pathElements += "c:\scripts"
$newPath = $pathElements -join ";"
[Environment]::SetEnvironmentVariable("path", $newPath, $scope)