#!/bin/bash

#http://serverfault.com/a/149685/103083
# impersonate www-data and then run uwsgi so that it can use /tmp/uwsgi.sock
#sudo su -s /bin/bash www-data -c 'uwsgi -s /tmp/uwsgi.sock --manage-script-name --mount /=run:app'

sed -i 's/DEBUG_MODE=False/DEBUG_MODE=True/' /home/cc-user/workspace/Flask-Simple-WebApp/run.py
sed -i "s/host='0.0.0.0', debug=DEBUG_MODE/host='0.0.0.0', port=8080, debug=DEBUG_MODE/" /home/cc-user/workspace/Flask-Simple-WebApp/run.py

sudo python /home/cc-user/workspace/Flask-Simple-WebApp/run.py

