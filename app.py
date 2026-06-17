from reports.report_generator import generate_pdf
from flask import Flask, render_template, request
from scanner.api_scanner import scan_api

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():

    api_url = request.form['api_url']

    results = scan_api(api_url)

    pdf_path = generate_pdf(results, api_url)

    return render_template(
    'result.html',
    api_url=api_url,
    results=results,
    pdf_path=pdf_path
)


if __name__ == '__main__':
    app.run(debug=True)