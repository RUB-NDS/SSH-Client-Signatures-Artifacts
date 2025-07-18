from web import WebInterface
from tool.FactorabilityTool import read_config

if __name__ == '__main__':
    config = read_config()
    WebInterface.run(config)
