import time
import random
import uuid

def get32UUID():
    # 生成一个 UUID4，并去掉其中的破折号，使其成为32个字符的字符串
    return str(uuid.uuid4()).replace("-", "")
def getUUID():
    # 生成一个UUID,直接转为大写
    return str(uuid.uuid4()).upper()
# map_id的生成方法
def generate_map_id():
    # 获取当前毫秒时间戳的最后6位
    millis = int(time.time() * 1000) % 1000000

    # 确保6位长度
    if millis < 100000:
        millis += 100000

    # 生成4位随机数 (1000-9999)
    rand_num = random.randint(1000, 9999)

    # 拼接为10位字符串
    return f"{millis}{rand_num}"


