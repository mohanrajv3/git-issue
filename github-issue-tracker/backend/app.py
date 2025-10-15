from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import re
import bleach

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///issues.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Input Validation Functions
def validate_input(text, field_name, max_length=200):
    """Validate and sanitize input"""
    if not text or not text.strip():
        return False, f"{field_name} cannot be empty"
    
    if len(text) > max_length:
        return False, f"{field_name} exceeds maximum length of {max_length}"
    
    # Check for SQL injection patterns
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|;|\/\*|\*\/|xp_|sp_)",
        r"('.*OR.*'.*=.*')"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return False, f"Invalid characters detected in {field_name}"
    
    # Sanitize HTML/XSS
    sanitized = bleach.clean(text, tags=[], strip=True)
    
    return True, sanitized

def validate_password(password):
    """Validate password strength"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain letters"
    
    if not re.search(r"[0-9]", password):
        return False, "Password must contain numbers"
    
    return True, "Valid"

def validate_status(status):
    """Validate issue status"""
    valid_statuses = ['Open', 'In Progress', 'Closed']
    if status not in valid_statuses:
        return False, f"Status must be one of: {', '.join(valid_statuses)}"
    return True, status

# Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validate username
    is_valid, result = validate_input(username, 'Username', 80)
    if not is_valid:
        return jsonify({'error': result}), 400
    
    # Validate password
    is_valid, message = validate_password(password)
    if not is_valid:
        return jsonify({'error': message}), 400
    
    # Check if user exists
    if User.query.filter_by(username=result).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    # Create user with hashed password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=result, password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'username': user.username
    }), 200

@app.route('/api/issues', methods=['GET'])
@token_required
def get_issues(current_user):
    """Get all issues"""
    issues = Issue.query.filter_by(user_id=current_user.id).all()
    
    issues_list = [{
        'id': issue.id,
        'title': issue.title,
        'description': issue.description,
        'status': issue.status,
        'created_at': issue.created_at.isoformat()
    } for issue in issues]
    
    return jsonify(issues_list), 200

@app.route('/api/issues', methods=['POST'])
@token_required
def create_issue(current_user):
    """Create new issue"""
    data = request.get_json()
    
    title = data.get('title', '')
    description = data.get('description', '')
    status = data.get('status', 'Open')
    
    # Validate title
    is_valid, result = validate_input(title, 'Title', 200)
    if not is_valid:
        return jsonify({'error': result}), 400
    title = result
    
    # Validate description
    is_valid, result = validate_input(description, 'Description', 1000)
    if not is_valid:
        return jsonify({'error': result}), 400
    description = result
    
    # Validate status
    is_valid, result = validate_status(status)
    if not is_valid:
        return jsonify({'error': result}), 400
    status = result
    
    # Create issue
    new_issue = Issue(
        title=title,
        description=description,
        status=status,
        user_id=current_user.id
    )
    
    db.session.add(new_issue)
    db.session.commit()
    
    return jsonify({
        'id': new_issue.id,
        'message': 'Issue created successfully'
    }), 201

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
@token_required
def update_issue(current_user, issue_id):
    """Update issue"""
    issue = Issue.query.filter_by(id=issue_id, user_id=current_user.id).first()
    
    if not issue:
        return jsonify({'error': 'Issue not found'}), 404
    
    data = request.get_json()
    
    if 'title' in data:
        is_valid, result = validate_input(data['title'], 'Title', 200)
        if not is_valid:
            return jsonify({'error': result}), 400
        issue.title = result
    
    if 'description' in data:
        is_valid, result = validate_input(data['description'], 'Description', 1000)
        if not is_valid:
            return jsonify({'error': result}), 400
        issue.description = result
    
    if 'status' in data:
        is_valid, result = validate_status(data['status'])
        if not is_valid:
            return jsonify({'error': result}), 400
        issue.status = result
    
    db.session.commit()
    
    return jsonify({'message': 'Issue updated successfully'}), 200

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
@token_required
def delete_issue(current_user, issue_id):
    """Delete issue"""
    issue = Issue.query.filter_by(id=issue_id, user_id=current_user.id).first()
    
    if not issue:
        return jsonify({'error': 'Issue not found'}), 404
    
    db.session.delete(issue)
    db.session.commit()
    
    return jsonify({'message': 'Issue deleted successfully'}), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default user if not exists
    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('Admin@123', method='pbkdf2:sha256')
        admin = User(username='admin', password=hashed_pw)
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)