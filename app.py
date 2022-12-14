from flask import Flask 
from flask import render_template
from flask import redirect
from flask import request
import mysql.connector
from flask_bcrypt import Bcrypt
from flask import session
from mysql.connector import pooling
from password import *

#connection pool 連線資料
poolname ="mysqlpool"
poolsize = 5
connectionpool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name =poolname,pool_size=poolsize, pool_reset_session=True, host='localhost',user='root',password=mySqlPassword())

#將 .get_connection() 存入 conn
def conn():
    try:
        c = connectionpool.get_connection()
        return c
    except:
        print ("connection error")
        exit(1)

#選擇資料庫
def selectDb(c):
    cursor = c.cursor()
    cursor.execute("USE website;") 
    return cursor
  

#密碼加密初始化
bcrypt = Bcrypt()

#session key
app =Flask(__name__)
app.secret_key= secret_key()


#首頁
@app.route("/")
def index():       
	return render_template("register.html")


#處理註冊
@app.route("/signup",methods=["POST"])
def signup():  
    c = conn()  #呼叫連線程式
    cursor = selectDb(c)
    with cursor:  #cursor 以下範圍內使用 cursor
        nickname = request.form["nickname"]
        username = request.form["username"]
        password = request.form["password"]
        sql = "SELECT username FROM member where username = %s"
        user = (username,)
        cursor.execute(sql, user)
        result = cursor.fetchall()
        if (not nickname or not username or not password):
            c.close()
            return redirect("/error?message=欄位不得爲空")
        if (result):   
            c.close()
            return redirect("/error?message=帳號已被註冊")
        else:
            hashed_password = bcrypt.generate_password_hash(password=password)
            sql = "Insert into member (name, username, password ) values (%s, %s, %s)"
            userInfo = (nickname, username, hashed_password)
            cursor.execute(sql, userInfo)
            c.commit()
            c.close()
            return redirect("/") 


#處理登入
@app.route("/login",methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    if (not username or not password):
        return redirect("/error?message=欄位不得爲空")

    c = conn()
    cursor = selectDb(c)
    with cursor:
        sql = "SELECT * FROM member where username = %s"
        user = (username,)
        cursor.execute(sql, user)
        result = cursor.fetchall()
        c.close()  

        if (result != []):
            user_id = result[0][0]
            hashed_password = result[0][3]
            check_password = bcrypt.check_password_hash(hashed_password, password)
            if ((f"{check_password}") == "True"):
                session['username'] = username
                session['password'] = password
                session['user_id'] = user_id                
                return redirect("/member")
               
    return redirect("/error?message=帳號或密碼錯誤")
    

#錯誤頁面
@app.route("/error")
def error():
    err = request.args.get("message", "出現錯誤")
    return render_template("loginFail.html", message = err)
  
	
#會員頁
@app.route("/member")
def member():
    username = session.get('username')
    password = session.get('password')

    if (username!= None and password != None):
        c = conn()
        cursor = selectDb(c)
        with cursor:
            sql = "SELECT password FROM member where username = %s"
            user = (username,)
            cursor.execute(sql, user)
            result = cursor.fetchall()
            hashed_password =result[0][0]
            check_password = bcrypt.check_password_hash(hashed_password, password)
            if ((f"{check_password}") == "True"):
                #取姓名、帳號、時間、內文
                sql = "select member.name, member.username, message.content, message.time from member inner join message on member.id = message.member_id order by message.time desc"
                cursor.execute(sql)
                result = cursor.fetchall()
                c.close() 
                return render_template("index.html", username=username, result=result)  
        c.close() 
    return redirect("/")

#處理登出
@app.route("/signout")
def signout():
    session.clear()
    return redirect("/")

#處理訊息
@app.route("/message",methods=["POST"])
def message():
    c = conn()
    cursor = selectDb(c)
    with cursor:
        cursor.execute("USE website;") 
        #從 session 取 user_id
        user_id = session.get('user_id')

        #插入 message 資料表
        content = request.form["content"]
        sql = "Insert into message (member_id, content) values (%s, %s)"
        user_content = (user_id, content)    
        cursor.execute(sql, user_content) 
        c.commit() 
        c.close() 
        return redirect("/member")


if __name__=="__main__": #如果以主程式進行
	app.run(port=3000) #立刻啟動伺服器
