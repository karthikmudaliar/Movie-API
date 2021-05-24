from flask import Flask, request, jsonify
from flask_restful import Resource, Api, reqparse, abort
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
api = Api(app)
auth = HTTPBasicAuth()

#Admin Creds
USER_DATA = {
	"admin": "helloworld"
}

#Verifying admin password
@auth.verify_password
def verify(username, password):
	if not (username and password):
		return False
	return USER_DATA.get(username) == password

#DataBase Configurations	
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'FyndMovies'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY']='Th1s1ss3cr3t'

mysql = MySQL(app)

#Verifying token validity
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
   
        try:
            # decoding the payload to fetch the stored details
        	data = jwt.decode(token, app.config[SECRET_KEY])
         # current_user = Users.query.filter_by(public_id=data['public_id']).first()
        	cur = mysql.connection.cursor()
        	cur.execute('''select * from users where public_id=%s''',[data['public_id']])
        	current_user = cur.fetchone()
        	mysql.connection.commit()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
   
    return decorated

#Function to register for new user    
@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
	data = request.get_json()  

	hashed_password = generate_password_hash(data['password'], method='sha256')
	public_id = str(uuid.uuid4())

	cur = mysql.connection.cursor()
	cur.execute('''INSERT INTO users(public_id, name, password) VALUES (%s, %s, %s)''', (public_id, data['name'], hashed_password))
	mysql.connection.commit()

	return jsonify({'message': 'registered successfully'})

#Function for logging in which return the public id access token
@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
 
	auth = request.authorization   

	if not auth or not auth.username or not auth.password:  
		return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

	# user = Users.query.filter_by(name=auth.username).first()   
	cur = mysql.connection.cursor()
	cur.execute('''select * from users where name=%s''',[auth.username])
	user = cur.fetchone()
	mysql.connection.commit()
	 
	if check_password_hash(user['password'], auth.password):  
		token = jwt.encode({'public_id': user['public_id'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
		return jsonify({'token' : token}), 201

	return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})

#FUnction to list all the registered users
@app.route('/users', methods=['GET'])
def get_all_users():

	cur = mysql.connection.cursor()
	cur.execute('''select * from users''')
	users = cur.fetchall()
	mysql.connection.commit()  

	result = []   
	content = {}
	for user in users:
		content = {'name':user['name'], 'public_id': user['public_id'], 'password': user['password'], 'admin': user['admin']}  
		result.append(content)
		content = {} 

	return jsonify({'users': result})

#Request Parser to validate all the Post method parameters
movie_post_args = reqparse.RequestParser()
movie_post_args.add_argument("99popularity", type=float, help="Add 99popularity of the movie", required=True)
movie_post_args.add_argument("director", type=str, help="Add director of the movie", required=True)
movie_post_args.add_argument("genre", type=int, help="Add genre of the movie", required=True)
movie_post_args.add_argument("imdb_score", type=float, help="Add imdb_score of the movie", required=True)
movie_post_args.add_argument("name", type=str, help="Add name of the movie", required=True)

#Request Parser to validate all the Get method Query parameters
movie_get_args = reqparse.RequestParser()
movie_get_args.add_argument("name", type=str, help="Name of the movie", required=False)
movie_get_args.add_argument("director", type=str, help="Director of the movie", required=False)

#Request Parser to validate all the Patch method parameters
movie_patch_args = reqparse.RequestParser()
movie_patch_args.add_argument("99popularity", type=float, help="Add 99popularity of the movie", required=True)
movie_patch_args.add_argument("director", type=str, help="Add director of the movie", required=True)
movie_patch_args.add_argument("genre", type=int, help="Add genre of the movie", required=True)
movie_patch_args.add_argument("imdb_score", type=float, help="Add imdb_score of the movie", required=True)
movie_patch_args.add_argument("name", type=str, help="Add name of the movie", required=True)

#Movies resource having post and get method
class Movies(Resource):
	#Post Method, input params: popularity, director, genre_id, imdb_score, name
	@auth.login_required
	def post(self):
		try:
			
			args = movie_post_args.parse_args()

			cur = mysql.connection.cursor()
			movie_data=request.get_json()

			#to check if valid genre ID is passed
			for genre_id in movie_data['genre']:
				cur.execute('''select g_name from genres where g_id = %s''',[genre_id])
				genre_name = cur.fetchone()
				if(genre_name == None):
					return {'message' :'Please Provide proper Genre ID'}, 404

			#get all the payload data
			popularity = movie_data['99popularity']
			director = movie_data['director']
			imdb_score = movie_data['imdb_score']
			name = movie_data['name']

			#insert movie resource to DB
			cur.execute('''INSERT INTO movies(99popularity, director, imdb_score, name) VALUES (%s, %s, %s, %s)''', (popularity, director, imdb_score, name))
			movie_id = cur.lastrowid

			#get genre names based on genre IDs
			list_mg = []
			for genre_id in movie_data['genre']:
				mg = (movie_id, genre_id)
				list_mg.append(mg)

			#insert Genre IDs mapping to Movie IDs in MovieGenres Relation Table
			sql = 'insert into moviegenres (f_m_id, f_g_id) VALUES (%s,%s)'
			cur.executemany(sql, list_mg)

			mysql.connection.commit()

			return({'message':'Resource Added Successfully!'}), 201
		except Exception as e:
			abort(500, message='Internal Server Error')

	#Get Method, returns all the movies
	def get(self):

		try:
			#Validating Query Parameters
			args = movie_get_args.parse_args()

			#Get Query Parameters
			movie_name = args['name']
			director = args['director']

			try:
				#Query for movie data based on the Query Parameters passed with all the cases (Movie Name, Movie Director)
				cur = mysql.connection.cursor()
				if(args['name'] and args['director'] == None):
					cur.execute('''select * from movies where m_visible=1 and name = %s''',[movie_name])
				elif(args['name'] == None and args['director']):
					cur.execute('''select * from movies where m_visible=1 and director = %s''',[director])
				elif(args['name']and args['director']):
					cur.execute('''select * from movies where m_visible=1 and director = %s or name = %s''',[director, movie_name])
				else:
					cur.execute('''select * from movies where m_visible=1''')
				results = cur.fetchall()
			except Exception as e:
				return {'Message': 'No movies found'}, 404
			json_data = []
			content = {}
			try:		
				for result in results:
					#Query for all the Genre IDS for each specific movie based on the Movie ID
					cur.execute('''select f_g_id from moviegenres where mg_visible=1 and f_m_id = %s''',[result['m_id']])
					genre_ids = cur.fetchall()
					genre_names = []

					for genre_id in genre_ids:
						#Query for all the Genre Name for each specific movie based on the Genre ID
						cur.execute('''select g_name from genres where g_id = %s''',[genre_id['f_g_id']])
						genre_name = cur.fetchone()
						genre_names.append(genre_name['g_name'])
					#Appending details in JSON format
					content = {'99popularity': result['99popularity'], 'director': result['director'], 'genre':genre_names, 'imdb_score': result['imdb_score'], 'name': result['name']}
					json_data.append(content)
					content = {}
				mysql.connection.commit()
			except Exception as e:
				abort(500, message='Internal Server Error')

			return json_data, 200

		except Exception as e:
			abort(500, message='Internal Server Error')

#Resource defined to perform actions based on Movie ID as URI Parameter
class MovieURI(Resource):
	#to GET movie details based on specific movie IS
	def get(self, movie_id):
		try: 
			#TO check in Movie ID is Valid
			cur = mysql.connection.cursor()
			cur.execute('''select * from movies where m_visible=1 and m_id = %s''',[movie_id])
			result = cur.fetchone()
			if(result is not None):
				try: 
					#Querying Movie details
					cur.execute('''select f_g_id from moviegenres where mg_visible=1 and f_m_id = %s''',[movie_id])
					genre_ids = cur.fetchall()
					genre_names = []
					for genre_id in genre_ids:
						#Querying Genre Names
						cur.execute('''select g_name from genres where g_id = %s''',[genre_id['f_g_id']])
						genre_name = cur.fetchone()
						genre_names.append(genre_name['g_name'])
					#Creating Response in JSON format
					content = {'99popularity': result['99popularity'], 'director': result['director'], 'genre':genre_names, 'imdb_score': result['imdb_score'], 'name': result['name']}
					mysql.connection.commit()

					return content, 200
				except Exception as e:
					abort(500, message='Internal Server Error')
			else:
				return {'message' :'Resource not found for the given ID'}, 404
		except Exception as e:
			abort(500, message='Internal Server Error')

	#Function to edit resource
	@auth.login_required
	def patch(self, movie_id):
		try:
			args = movie_patch_args.parse_args()

			cur = mysql.connection.cursor()
			#TO check if Movie ID is Valid
			cur.execute('''select * from movies where m_visible=1 and m_id = %s''',[movie_id])
			result = cur.fetchone()
			if(result is not None):

				try:
					movie_data=request.get_json()
					#TO check if Genre ID is Valid
					for genre_id in movie_data['genre']:
						cur.execute('''select g_name from genres where g_id = %s''',[genre_id])
						genre_name = cur.fetchone()
						if(genre_name == None):
							return {'message' :'Please Provide proper Genre ID'}, 404	

					#get all the payload data
					popularity = movie_data['99popularity']
					director = movie_data['director']
					imdb_score = movie_data['imdb_score']
					name = movie_data['name']

					#update query for movies
					cur.execute('''update movies set 99popularity = %s, director = %s, imdb_score = %s, name = %s where m_id = %s''',[popularity, director, imdb_score, name, movie_id])
					cur.execute('''select mg_id from moviegenres where f_m_id = %s''',[movie_id])
					mg_ids = cur.fetchall()
					list_mg = []
					#Updating MovieGenre Relation Table
					for i in range(0,len(mg_ids)):
						cur.execute('''update moviegenres set f_g_id = %s where mg_visible = 1 and mg_id = %s''',[movie_data['genre'][i], mg_ids[i]['mg_id']])
					mysql.connection.commit()
					return {'message' : 'Resource Updated Successfully!'}, 200

				except Exception as e:
					abort(500, message='Internal Server Error')

			else:
				return {'message' :'Resource not found for the given ID'}, 404

		except Exception as e:
			abort(500, message='Internal Server Error')

	#Funtion to delete the movie resource 
	@auth.login_required
	def delete(self, movie_id):
		try: 
			#TO check if Movie ID is valid
			cur = mysql.connection.cursor()
			cur.execute('''select * from movies where m_visible=1 and m_id = %s''',[movie_id])
			result = cur.fetchone()
			if(result is not None):
				#Query for soft delete for movie resource
				cur.execute('''update movies set m_visible=0 where m_id = %s''',[movie_id])
				cur.execute('''update moviegenres set mg_visible=0 where f_m_id = %s''',[movie_id])
				mysql.connection.commit()

				return {'message' : 'Resource Deleted Successfully!'}, 200
			else: 
				return {'message' :'Resource not found for the given ID'}, 404
		except Exception as e:
			abort(500, message='Internal Server Error')

#Adding resources
api.add_resource(Movies, '/movies')
api.add_resource(MovieURI,'/movie/<int:movie_id>')

if __name__ == '__main__':
    app.run(debug=True)