
import unittest
import json
import requests

class MoviesTest(unittest.TestCase):

	API_URL = "http://127.0.0.1:5000/movies"
	API_URL_URI = "http://127.0.0.1:5000/movie"

	#check for response 200
	def test_post_movies(self):

		payload =   {
					"99popularity": 86.0,
					"director": "Orson Welles",
					"genre": [
					  1,2
					],
					"imdb_score": 8.6,
					"name": "Citizen Kane"
					}

		r = requests.post(MoviesTest.API_URL, json=payload)
		self.assertEqual(r.status_code, 201)

	def test_post_movies_failure(self):
		payload =   {
			"99popularity": 86.0,
			"director": "Orson Welles",
			"genre": [
			  "Drama","War"
			],
			"imdb_score": 8.6,
			"name": "Citizen Kane"
			}

		r = requests.post(MoviesTest.API_URL, json=payload)
		self.assertEqual(r.status_code, 500)

	def test_get_movies(self):

		r = requests.get(MoviesTest.API_URL)
		self.assertEqual(r.status_code, 200)

	def test_get_movie_uri(self):
		id = 15
		r = requests.get("{}/{}".format(MoviesTest.API_URL_URI, id))
		self.assertEqual(r.status_code, 200)

	def test_patch_movie(self):
		id = 14
		payload =   {
					"99popularity": 86.0,
					"director": "Orson Welles",
					"genre": [
					  1,2
					],
					"imdb_score": 8.6,
					"name": "Citizen Kane"
					}

		r = requests.patch("{}/{}".format(MoviesTest.API_URL_URI, id), json=payload)
		self.assertEqual(r.status_code, 200)

	def test_patch_movie_notfound(self):
		id = 14
		payload =   {
					"99popularity": 86.0,
					"director": "Orson Welles",
					"genre": [
					  1,98
					],
					"imdb_score": 8.6,
					"name": "Citizen Kane"
					}

		r = requests.patch("{}/{}".format(MoviesTest.API_URL_URI, id), json=payload)
		self.assertEqual(r.status_code, 404)


	def test_patch_movie_Failure(self):
		id = 14
		payload =   {
					"99popularity": 86.0,
					"director": "Orson Welles",
					"genre": [
					  1,98
					],
					"imdb_score": 8.6
					}

		r = requests.patch("{}/{}".format(MoviesTest.API_URL_URI, id), json=payload)
		self.assertEqual(r.status_code, 500)

	def test_delete_movie(self):
		id = 1
		r = requests.delete("{}/{}".format(MoviesTest.API_URL_URI, id))
		self.assertEqual(r.status_code, 200)

	def test_delete_movie_notfound(self):
		id = 100
		r = requests.delete("{}/{}".format(MoviesTest.API_URL_URI, id))
		self.assertEqual(r.status_code, 404)

