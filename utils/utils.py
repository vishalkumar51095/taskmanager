import datetime

formats = ['%d-%m-%Y', '%Y-%m-%d']


def success_response(message):
    return {'message': message, 'success': True}


def error_response(message):
    return {'message': message, 'success': False}


def parse_date(date):
    date = date.split('T', 1)[0]
    for date_format in formats:
        try:
            return datetime.datetime.strptime(date, date_format)
        except:
            continue
