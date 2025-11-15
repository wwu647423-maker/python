def check(money):
  print(f"你的余额：{money}")
def inport(money):
  print(f"你的余额：{money}")
  account=int(input("请输入你想存入的金额："))
  money=money+account
  print(f"你的余额：{money}")
def outport(money):
  print(f"你的余额：{money}")
  account=int (input("请输入你想取出的金额："))
  if account>money:
    print(f"余额不足，你的余额为{money}")
  else:
   money=money-account
   print(f"你的余额：{money}")
def main():
 print("----1.查询余额----")
 print("------2.存款------")
 print("------3.取款------")
 print("------4.退出------")
money=50000000
name=input("请输入你的姓名：")
main()
while(1):
  choose=int(input())
  if choose==1 :
    check(money)
  elif choose==2 :
    inport(money)
  elif choose==3 :
    outport(money)
  elif choose==4 :
    break