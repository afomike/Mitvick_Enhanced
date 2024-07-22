from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attack_cycle.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

# Home Route
@app.route('/')
def index():
    return render_template('index.html')

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
        return redirect(url_for('index'))  # Redirect to the homepage or another suitable page
    return render_template('retreat.html')

if __name__ == '__main__':
    app.run(debug=True)
