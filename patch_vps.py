import os
import re

app_js = "miniapp/app.js"
if os.path.exists(app_js):
    with open(app_js, "r") as f:
        content = f.read()
    # Fix syntax error
    content = content.replace("    });\n    });\n\n    // Add another", "    });\n\n    // Add another")
    # Fix CloudStorage
    content = content.replace("tg?.SecureStorage", "tg?.CloudStorage")
    with open(app_js, "w") as f:
        f.write(content)
    print("Fixed app.js")

bot_py = "bot.py"
if os.path.exists(bot_py):
    with open(bot_py, "r") as f:
        content = f.read()
    # Fix markdown
    content = content.replace("MarkdownV2", "HTML")
    content = re.sub(r'\\([.\(\)\[\]\-\_])', r'\1', content)
    with open(bot_py, "w") as f:
        f.write(content)
    print("Fixed bot.py")
