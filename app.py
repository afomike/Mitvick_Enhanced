import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# app.secret_key = os.urandom(12).hex()
app.config['SECRET_KEY'] = os.urandom(12).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attack_cycle.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Define the models for each phase
class InformationGathering(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_name = db.Column(db.String(100))
    target_email = db.Column(db.String(100))
    target_phone = db.Column(db.String(20))
    target_address = db.Column(db.String(200))
    target_company = db.Column(db.String(100))
    additional_info = db.Column(db.Text)

class DevelopingRelationships(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    relationship_type = db.Column(db.String(100))
    interaction_methods = db.Column(db.Text)
    interaction_outcomes = db.Column(db.Text)

class ExploitingRelationships(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exploitation_method = db.Column(db.String(100))
    exploited_info = db.Column(db.Text)
    expected_outcome = db.Column(db.Text)

class ExecutionOfAttack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attack_method = db.Column(db.String(100))
    attack_target = db.Column(db.String(100))
    attack_details = db.Column(db.Text)
    outcome = db.Column(db.Text)

class AchievingObjective(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    objective_achieved = db.Column(db.String(100))
    achievements = db.Column(db.Text)
    next_steps = db.Column(db.Text)

class Retreat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retreat_method = db.Column(db.String(100))
    retreat_details = db.Column(db.Text)
    reflection = db.Column(db.Text)

# Create the database and tables
with app.app_context():
    db.create_all()

# Define routes and view functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')
        
        # Create a new user with the hashed password
        new_user = User(username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
# Home Route
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/gather_info', methods=['GET', 'POST'])
def gather_info():
    if request.method == 'POST':
        data = InformationGathering(
            target_name=request.form['target_name'],
            target_email=request.form['target_email'],
            target_phone=request.form['target_phone'],
            target_address=request.form['target_address'],
            target_company=request.form['target_company'],
            additional_info=request.form.get('additional_info')
        )
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('develop_relationships'))
    return render_template('gather_info.html')

@app.route('/develop_relationships', methods=['GET', 'POST'])
def develop_relationships():
    if request.method == 'POST':
        data = DevelopingRelationships(
            relationship_type=request.form['relationship_type'],
            interaction_methods=request.form.get('interaction_methods'),
            interaction_outcomes=request.form.get('interaction_outcomes')
        )
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('exploit_relationships'))
    return render_template('develop_relationships.html')

@app.route('/exploit_relationships', methods=['GET', 'POST'])
def exploit_relationships():
    if request.method == 'POST':
        data = ExploitingRelationships(
            exploitation_method=request.form['exploitation_method'],
            exploited_info=request.form.get('exploited_info'),
            expected_outcome=request.form.get('expected_outcome')
        )
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('execute_attack'))
    return render_template('exploit_relationships.html')

@app.route('/execute_attack', methods=['GET', 'POST'])
def execute_attack():
    if request.method == 'POST':
        data = ExecutionOfAttack(
            attack_method=request.form['attack_method'],
            attack_target=request.form['attack_target'],
            attack_details=request.form.get('attack_details'),
            outcome=request.form.get('outcome')
        )
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('achieve_objective'))
    return render_template('execute_attack.html')

@app.route('/achieve_objective', methods=['GET', 'POST'])
def achieve_objective():
    if request.method == 'POST':
        data = AchievingObjective(
            objective_achieved=request.form['objective_achieved'],
            achievements=request.form.get('achievements'),
            next_steps=request.form.get('next_steps')
        )
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('retreat'))
    return render_template('achieve_objective.html')

@app.route('/final')
def final():
    return render_template('final.html')

@app.route('/retreat', methods=['GET', 'POST'])
def retreat():
    if request.method == 'POST':
        data = Retreat(
            retreat_method=request.form['retreat_method'],
            retreat_details=request.form.get('retreat_details'),
            reflection=request.form.get('reflection')
        )
        db.session.add(data)
        db.session.commit()
        return redirect(url_for('final'))  # Redirect to the final page
    return render_template('retreat.html')

@app.route('/view_entries')
def view_entries():
    information_gathering = InformationGathering.query.all()
    developing_relationships = DevelopingRelationships.query.all()
    exploiting_relationships = ExploitingRelationships.query.all()
    execution_of_attack = ExecutionOfAttack.query.all()
    achieving_objective = AchievingObjective.query.all()
    retreat = Retreat.query.all()
    
    return render_template('view_entries.html', 
                           information_gathering=information_gathering,
                           developing_relationships=developing_relationships,
                           exploiting_relationships=exploiting_relationships,
                           execution_of_attack=execution_of_attack,
                           achieving_objective=achieving_objective,
                           retreat=retreat)

@app.route('/edit_entry/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    entry = InformationGathering.query.get_or_404(entry_id)
    if request.method == 'POST':
        entry.target_name = request.form['target_name']
        entry.target_email = request.form['target_email']
        entry.target_phone = request.form['target_phone']
        entry.target_address = request.form['target_address']
        entry.target_company = request.form['target_company']
        entry.additional_info = request.form['additional_info']
        db.session.commit()
        return redirect(url_for('view_entries'))
    return render_template('edit_entry.html', entry=entry)

@app.route('/delete_entry/<int:entry_id>', methods=['POST'])
def delete_entry(entry_id):
    entry = InformationGathering.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('view_entries'))

if __name__ == '__main__':
    app.run(debug=True)
