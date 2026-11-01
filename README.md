# vscan-exposed-env-var-detector
Detects potentially sensitive environment variables exposed in web application responses or configuration files. Uses heuristics and regular expressions to identify common patterns like API keys, database passwords, and secret keys. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-exposed-env-var-detector`

## Usage
`./vscan-exposed-env-var-detector [params]`

Findings report the pattern kind and the variable name only. Matched values are shown as [MASKED] in the printed results and in the output file, and are never saved in clear. An invalid URL or a failed fetch prints a failure line and exits with status 1.

## Parameters
- `-h`: Show help message and exit
- `-o`: Output file to save results to.
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
