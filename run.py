# Run a test server
from web_app import app
if __name__ == '__main__':
     app.run(host='0.0.0.0',port=8080,debug=False)
     print("App running on port 8082")

