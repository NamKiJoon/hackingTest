from flask import Flask, render_template

app = Flask(__name__)

app.config['DEBUG'] = True

@app.route('/')
def home():
    print("123")
    return "Flask."

@app.route('/test')
def test():
    numbers = [1, 2, 3, 4, 7]
    sum_result = sum(numbers)
    result = f"숫자 {numbers}의 합: {sum_result}"
    
    return result

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)