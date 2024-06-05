

gen:
    buf generate

build:
    #!/usr/bin/env -S parallel --shebang --ungroup --jobs 2
    GOOS=linux GOARCH=arm64 go build -o bin/iotnetlab-linux-arm64
    GOOS=linux GOARCH=amd64 go build -o bin/iotnetlab-linux-amd64

copy:
    #!/usr/bin/env -S parallel --shebang --ungroup --jobs 3
    upx -9 bin/iotnetlab-linux-arm64 && rsync -LaPz --progress bin/iotnetlab-linux-arm64 isaac@asahi-mini:iotnetlab
#    upx -9 bin/iotnetlab-linux-amd64 && rsync -LaPz --progress bin/iotnetlab-linux-amd64 isaac@silicafractal:iotnetlab
#    upx -9 bin/iotnetlab-linux-amd64 && rsync -LaPz --progress bin/iotnetlab-linux-amd64 isaac@fw-hex:iotnetlab

deploy: build copy
