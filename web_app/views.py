from web_app import *
from werkzeug.security import generate_password_hash
from project.token import generate_confirmation_token, confirm_token
import hashlib, binascii
import datetime



@app.route('/')
@login_required #added to prevent from login
def home():
    # get complete email list
    return render_template('home.html');


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' :
        #print("username: ",form.username.data,"\n\n\n");
       # return str(form.username.data)
        user=dict();
        try:
            user = mongo.db.users.find_one({"_id":form.username.data})
        #    print('name: ',user['name'], 'password: ',user['password'])
        except Exception as e:
            return str(e)
        #return user['password']    
        if user and User.validate_login(user['password'], form.password.data):
           # return 'inside'
           # print("data: ",form.password.data)
            if user["status"]=="deactivated":
                return "Account has not been activated yet, Please check your mail and verify yourself."
            user_obj = User(user['_id'])
            login_user(user_obj)
            flash("Logged in successfully!", category='success')
            return redirect(request.args.get("next") or url_for("home"))
            #home();
            
        flash("Wrong username or password!", category='error')
    print('here');
    return render_template('login.html', title='login', form=form)


@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
        
    return redirect(url_for('home.html'))



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    verified=False;
    if request.method == 'POST':
        
        pass_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        verified = True;
        k = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 100000)
        stoken = binascii.hexlify(k)
        print(stoken)
        # Insert the user in the DB
        try:
            mongo.db.users.insert({"_id": form.username.data, "password": pass_hash, "email": form.email.data,"status":"activated","key":stoken})
            #return 'Welcome! Thanks for signing up. Please follow this link in your email to activate your account:'
            return 'Welcome! Thanks for signing up, Please follow to the link to Login <a href="/login">Login</a>'
        # except DuplicateKeyError:
        #     return 'user alreaday exist'
        except Exception as e:
            if 'duplicate key' in str(e):
                return "A user with that credentials already exist!"
            return  str(e);#"User already present in DB."

        #user = mongo.db.users.find_one({"_id": form.username.data})
        
        token = generate_confirmation_token(user.email)
        
    
    return render_template('signup.html', title='signup', form=form)


@app.route('/inner', methods=['GET', 'POST'])
@login_required
def inner():
    global ic
    name = request.form['name']
    password = request.form['password']
    if name == "" or password == "":
        return render_template('index.html');
    else:
        # Reading the file everytime will degrade the function performance
       # df = pd.read_csv("login.csv", sep=',', encoding="utf-8")
        #for index,row in df.iterrows():
        #    if row['name'] == name and row['password'] == password:
         #       print('sucess')
         #       return render_template('inner.html');
        data = "       PLEASE ENTER VALID USERNAME AND PASSWORD TO LOGIN               "
        return render_template('index.html', records=data, title='User');

@app.route('/email', methods=['POST'])
@login_required
def handle_email():
    email = request.form['email']
    url = "http://spiderapi.herokuapp.com/api/emails/"
    print("requesting: ", url)
    headers = {'Content-type': 'application/json'}
    r = requests.post(url, json={"email": email, "key": "C88B933A691E16C56EBC92BCC9A7E"}, headers=headers)
    print(r.json())
    if r.status_code == 200:
        return jsonify(r.json()), 200
    else:
        return jsonify({"response": " Something when wrong ", "status_code": 400});


@app.route('/emails', methods=['GET', 'POST'])
@login_required
def handle_emailList():
    if request.method == 'GET':
        return "Hello getter"
    elif request.method == 'POST':
        req_id = 'file' + datetime.now().strftime(FORMAT)
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            try:
                email_list = parse_csv(UPLOAD_FOLDER + filename)
                # print("init.py: email list: ",email_list[0])
                print("init.py: Email list length: ", len(email_list))
                for i in email_list:
                    print(i)
                email_list = [email for email in email_list if email['email'] is not '']
                list_size = len(email_list);
                req_id += '_{0}'.format(list_size);
                print("parsed length:", list_size)
                executor.submit(parse_csv_pool, email_list, req_id)
                return redirect(url_for('results', rid=req_id))
                # return 'One jobs was launched in background with id: {0}'.format(req_id)
            except Exception as e:
                return str(e);
        else:
            return jsonify({'code': 400, 'message': 'No interface defined for URL'}), 400


@app.route('/results', methods=['GET'])
@login_required
def results():
    req_id = request.args['rid']
    return render_template('result.html', req_id=req_id);


@app.route('/guess', methods=['GET', 'POST'])
@login_required
def guess_email():
    if request.method == 'POST':
        req_id = 'file' + datetime.now().strftime(FORMAT)
        fname = request.form['fname']
        lname = request.form['lname']
        dname = request.form['dname']
        e = EmailPermutator()
        email_list = e.get_emails(fname=fname, lname=lname, dname=dname)
        for i, email in enumerate(email_list):
            email_list[i] = {'email': email}
        list_size = len(email_list);
        req_id += '_{0}'.format(list_size);
        print("parsed length:", list_size)
        executor.submit(parse_csv_pool, email_list, req_id)
        # return jsonify({"response":req_id,"url":'/results?rid='+req_id});
        return redirect(url_for('results', rid=req_id))
    return "Hello"


def recursive_len(item):
    if type(item) == list:
        return sum(recursive_len(subitem) for subitem in item)
    else:
        return 1


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/getuser', methods=['POST'])
def getuser():
    iname = request.form['iname']
    iemail = request.form['iemail']
    ipassword = request.form['ipassword']
    if (iname == "" or iemail == "" or ipassword == ""):
        return render_template('index.html');
    else:
       # df = pd.read_csv("login.csv", sep=',', encoding="utf-8")
        #df2 = df.append(pd.DataFrame([[iname, ipassword, iemail]], columns
    #    =df.columns))
     #   df2.to_csv("login.csv", index=False)
      #  print()
        data = "       USER SUCESSFULLY CREATED NOW YOU CAN LOGIN               "
        return render_template('index.html', records=data, title='User');


@app.route('/guesses', methods=['GET', 'POST'])
def handle_guessList():
    if request.method == 'GET':
        return "Hello getter"
    elif request.method == 'POST':
        req_id = 'guess' + datetime.now().strftime(FORMAT)
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            try:
                guess_list = parse_csv(UPLOAD_FOLDER + filename)
                print("init.py:/guesses: Email list length: ", len(guess_list))
                # print("init.py:/guesses: email list: ",guess_list[0])

                # for i in guess_list:
                #     print(i)
                if ('firstname' not in guess_list[0].keys()):
                    return 'firstname column not present in csv!';
                elif ('lastname' not in guess_list[0].keys()):
                    return 'lastname column not present in csv!';
                elif ('domain' not in guess_list[0].keys()):
                    return 'domain column not present in csv!';

                e = EmailPermutator();
                # print("init.py:/guesses: type of list[0]",type(guess_list[0]));
                tmp_list = guess_list;
                for person in tmp_list:
                    person['email'] = e.get_emails(person['firstname'], person['lastname'], person['domain']);

                tmp_emails = [];
                for person in tmp_list:
                    each_persons_list = []
                    for email in person['email']:
                        tmp_person = person.copy();
                        tmp_person['email'] = email;
                        each_persons_list.append(tmp_person);
                    tmp_emails.append(each_persons_list);

                print("type: tmp_emails[0]", type(tmp_emails[0]));

                # tmp_emails2 = [[person.copy()] for person in tmp_list for email in person['email']]
                # print("tmp_emails2",len(tmp_emails2));
                # print("#################");
                # print("init.py: tmp_list: ");
                # print(tmp_emails);
                # print("##################");

                #  email_list = [{'firstname':client['firstname'],'lastname':client['lastname'],'domain':client['domain'],'emails':e.get_emails(client['firstname'],client['lastname'],client['domain'])} for client in guess_list];
                #  emails = [[{'email':i,'firstname':client['firstname'],'lastname':client['lastname'],'domain':client['domain']} for i in client['emails']] for client in email_list]
                list_size = recursive_len(tmp_emails);
                req_id += '_{0}'.format(list_size);
                executor.submit(guess_pool, tmp_emails, req_id)
                # return redirect(url_for('results',rid=req_id))
                # return 'One jobs was launched in background with id: {0}'.format(req_id)
                # return str(emails);
                return redirect(url_for('results', rid=req_id))
            except Exception as e:
                print(e);
                return 'Guesses:Something went wrong while parsing, Error: ' + str(e);
        else:
            return jsonify({'code': 400, 'message': 'No interface defined for URL'}), 400


@app.route('/singleD', methods=['GET', 'POST'])
@login_required
def one_domain():
    if request.method == 'POST':
        req_id = 'file' + datetime.now().strftime(FORMAT)
        cname = request.form['cname']
        data = clearbit.NameToDomain.find(name=cname)
        flash(data)
        '''for i, email in enumerate(email_list):
            email_list[i] = {'email': email}
        list_size = len(email_list);
        req_id += '_{0}'.format(list_size);
        print("parsed length:", list_size)
        executor.submit(parse_csv_pool, email_list, req_id)
        #return jsonify({"response":req_id,"url":'/results?rid='+req_id});
        return redirect(url_for('results', rid=req_id))'''
    return "Hello"

@lm.user_loader
def load_user(username):
    u = mongo.db.users.find_one({"_id": username})
    if not u:
        return None
    return User(u['_id'])
