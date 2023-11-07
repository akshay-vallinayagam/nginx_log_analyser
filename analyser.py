#!/usr/bin/env python3
"""Analyses NGINX access log and provides some useful statistics."""

import sys
import logging
from argparse import Namespace, ArgumentParser
import user_agents

# Global variable for response size limit more than which will be considered unusual
RESPONSE_SIZE_LIMIT = 8000


def parse_each_log(each_log: str) -> dict[str, str]:
    """Parse a log string and return the parameters as a dictionary."""
    log_entry = [item.strip() for item in each_log.split('"') if item.strip() != ""]

    # logging.debug("log entry format %s", log_entry)

    # Extract IP and timestamp from a string like this '169.25.170.239 - - [07/Feb/2023:06:34:49 +0000]'
    ip_and_timestamp = log_entry[0].split()
    ip_address = ip_and_timestamp[0]
    timestamp = ip_and_timestamp[-1][1:-1]  # removed the square brackets in timestamp
    http_method, url, protocol = log_entry[1].split()
    status, response_size = log_entry[2].split()
    referrer_url = log_entry[3]
    user_agent = log_entry[4]

    return {
        "IP Address": ip_address,
        "Timestamp": timestamp,
        "HTTP Method": http_method,
        "Requested URL": url,
        "HTTP Protocol": protocol,
        "Status Code": status,
        "Response Size": response_size,
        "Referrer URL": referrer_url,
        "User Agent": user_agent,
    }


def parse_log_file(filepath: str) -> list[dict]:
    """Read each line in a log file and returns a list of dicts with all parameters."""
    try:
        with open(filepath, mode="r", encoding="utf-8") as logfile:
            return [parse_each_log(log) for log in logfile if log != ""]
    except FileNotFoundError:
        return []


def get_http_method_metric(log: dict[str, str], http_method_metric: dict[str, dict[str, int]]) -> None:
    """Update the count for each http method in the input metrics."""
    # logging.debug("http_method_metric %s", http_method_metric)

    http_method = log["HTTP Method"]
    http_response_size = int(log["Response Size"])

    # Setting default value to the metrics. Returns the current value of the http_method if it already exists
    metric = http_method_metric.setdefault(http_method, {"count": 0, "odd_response_sizes": []})
    metric["count"] += 1

    # Check for odd response sizes based on the global variable set
    if http_response_size >= RESPONSE_SIZE_LIMIT:
        metric["odd_response_sizes"].append(http_response_size)

    http_method_metric[http_method] = metric


def get_user_agent_metric(log: dict[str, str], user_agent_metric: dict[str, dict[str, int or list[str]]]) -> None:
    """Update the metrics for user agent in the input dictionary."""
    # logging.debug("user_agent_metric %s", user_agent_metric)

    browser = user_agents.parse(log["User Agent"])
    browser_name = browser.browser.family
    browser_version = browser.browser.version_string

    # Setting default value to the metrics. Returns the current value of the browser_name if it already exists
    metric = user_agent_metric.setdefault(browser_name, {"count": 0, "versions": []})

    # Update the count and versions in the metrics
    metric["count"] += 1
    if browser_version not in metric["versions"]:
        metric["versions"].append(browser_version)

    user_agent_metric[browser_name] = metric


def get_ip_based_metric(log: dict[str, str], ip_based_metric: dict[str, int], ip_list: list[str]) -> None:
    """Get the stats of IP addresses that occurs more than once."""
    # logging.debug("ip_based_metric %s", ip_based_metric)
    ip_addr = log["IP Address"]
    # ip_list is the unique IP list
    # Update ip_based_metric if ip_addr exists in the unique IP list

    if ip_addr in ip_list:
        if ip_addr in ip_based_metric:
            ip_based_metric[ip_addr] += 1
        else:
            ip_based_metric[ip_addr] = 2  # Starting from 2 due to the initial entry in ip_list
    else:
        # If the IP address is not in the unique IP list, add it to the list.
        ip_list.append(ip_addr)


def get_metrics_from_log(loglist: list[dict]) -> list[dict]:
    """Get all the useful metrics from the logs."""
    http_method_metric = {}
    user_agent_metric = {}
    ip_list, ip_based_metric = [], {}

    for log in loglist:
        get_http_method_metric(log, http_method_metric)
        get_user_agent_metric(log, user_agent_metric)
        get_ip_based_metric(log, ip_based_metric, ip_list)
    return [http_method_metric, user_agent_metric, ip_based_metric]


def set_logging_config(debug_flag: bool) -> None:
    """Set the configuration needed for logging."""
    # Configure the logging module based on the debug_flag
    # If debug_flag is True, set logging level to DEBUG; otherwise, use INFO
    logging.basicConfig(
        level=logging.DEBUG if debug_flag else logging.INFO,
        format="[%(levelname)s] %(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            # Log to the console (stdout)
            logging.StreamHandler(sys.stdout),
        ],
    )


def main(args: Namespace) -> list[dict]:
    """Run main."""
    set_logging_config(args.debug)
    logging.info("Script execution started")

    log_file = args.file
    if log_file:
        logging.info("Parsing the log file...")
        parsed_log_list = parse_log_file(log_file)

        if not parsed_log_list:
            logging.error("Input file does not exist or is empty")
            logging.info("Exiting")
            sys.exit(-1)

        http_method_metric, user_agent_metric, ip_based_metric = get_metrics_from_log(parsed_log_list)
        logging.info("Http methods and odd response sizes: %s", http_method_metric)
        logging.info("User agents: %s", user_agent_metric)
        logging.info("Repeated IP addresses: %s", ip_based_metric)
        logging.info("Script execution completed")
    else:
        logging.error("No input file provided. Please check the usage (analyser.py --help)")
        logging.info("Exiting")
        sys.exit(-1)


if __name__ == "__main__":
    parser = ArgumentParser(
        prog="NGINX Analyser",
        description="Analyses a NGINX access log and provides some useful statistics",
        epilog="Built with Python",
    )

    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-f", "--file", default=None, help="Path to the nginx log file")

    main(parser.parse_args())
