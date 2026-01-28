$action = $args[0]
$restOfArgs = $args[1..($args.Count - 1)]

if ($action -eq "build") {
    docker build . -t rbaxim/mop:latest
    exit 0
}
elseif ($action -eq "run") {
    docker run -it -p 8080:8080 -p 8000:8000 -v "${PWD}/moppy:/moapy/moppy" -v "${PWD}/scripts:/moapy/scripts" rbaxim/mop $restOfArgs
}
else {
    Write-Host "Usage: .\mop-docker.ps1 [build|run]" -ForegroundColor Yellow
}