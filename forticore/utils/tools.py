import subprocess
from ..utils.logger import Logger

logger = Logger.get_logger(__name__)

def check_and_install_tools(tools):
    for tool in tools:
        try:
            tool_availability = subprocess.run(
                ["which", tool], 
                capture_output=True, 
                text=True
            )
            if not tool_availability.stdout.strip():
                logger.info(f"Installing {tool} ...")
                try:
                    installation = subprocess.run(
                        ["sudo", "apt", "install", tool, "-y"], 
                        check=True
                    )
                    logger.info(f"{tool} successfully installed")
                except subprocess.CalledProcessError:
                    logger.error(f"Failed to install {tool}")
                    logger.info(
                        f"Visit https://forticore/troubleshoot/tools/{tool} "
                        "to get details on how to install {tool}"
                    )
                    exit()
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")

def update_tools():
    try:
        subprocess.run(["sudo", "apt", "upgrade", "-y"])
        logger.info("All tools updated")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        exit()
