def check (data):
    if data>37:
        print(f"你的体温是{data},你发烧了")
    else:
        print(f"你的体温是{data}，你的体温正常")
import random
tem=random.randint(36,40)

check (tem)
