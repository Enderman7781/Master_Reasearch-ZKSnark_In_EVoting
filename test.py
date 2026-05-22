import pandas as pd
from zk_normal import FILE_PATH

# 讀取你的真實 CSV 檔案
df = pd.read_csv(FILE_PATH['csv'])

print(f"Excel 說的總行數: {len(df)}")

# 假設你的 CSV 裡 ID 欄位名稱叫做 'hashId' 或 'id'，請自行替換下方字串
# 如果不確定欄位叫什麼，可以加上 print(df.columns) 看一下
print(f"Python 看到的【真正不重複 ID】數量: {df['studentId'].nunique()}")

# 抽查第 95 到 105 筆資料，看看數字有沒有變成科學記號或被補零
print("\n--- 案發現場抽查 (Row 95-105) ---")
print(df['studentId'].iloc[95:105])