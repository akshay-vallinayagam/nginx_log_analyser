# NGINX Analyser 

This tool allows you to get useful statistics from the NGINX access log file.

## Pre-requisites

- Python 3.10+
- user_agents (install with: pip install user-agents)

## Setup (One-time setup)

1. Clone this repository and navigate to the directory:
   ```
   git clone https://github.com/akshay-vallinayagam/nginx_log_analyser.git && cd nginx_log_analyser
   ```

## Usage Instructions

To parse and get the metrics from the NGINX log file, use the following command:

```
python3 analyser.py [-d|--debug] [-h|--help] [-f|--file FILE_PATH]
```

Options:
- -h, --help: 					      show this help message and exit
- -d, --debug: 					   Enable debug logging (Optional)
- -f, --file FILE_PATH: 	      Path to the NGINX log file

Example usages:

```sh
python3 analyser.py --file access.log --debug
python3 analyser.py -f access1.log -d > test.txt
```

## About

The script requires the input log file as mandatory argument.

The tool will analyze the log file and provides insights on
   - Distribution of HTTP requests (how many PUT, GET, etc.)
   - User agents being used
   - Statistics by IP address (Are we seeing repeat visitors?)
   - Request sizes x request types (Any odd request sizes?)

The output will be printed to STDOUT by default which can be redirected to a file if needed

## Future Enhancements

We have plans to expand the functionality of the tool by providing more useful metrics on the logs and make the tool more efficient

Thank you for using the NGINX Analyser.