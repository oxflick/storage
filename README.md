<h1>Storage App using Flask and SQLAlchemy</h1>

<p> In this project I developed a RESTful web application using the Python framework that provides a list of rooms and storages in these rooms. I integrated third party user registration and authentication. Authenticated users have the ability to add and edit a room, as well as post, edit and delete the storages in their rooms. I also implemented JSON and XML endpoints. And for the responsiveness I used Bootstrap Framework. </p>

<h1> Setting up the Environment and Installation </h1>

1. Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads) and [Vagrant](https://www.vagrantup.com/downloads)
2. Clone Storage repository by typing in Terminal 'git clone https://github.com/oxflick/storage.git'.
3. Move to the project folder by typing in Terminal 'cd storage'.
4. Launch the Vagrant by typing: 'vagrant up'.
5. Log into Vagrant by typing: 'vagrant ssh'.
6. Type 'cd /vagrant' and move to the project folder 'cd storage'.
7. Run the application within the Vagrant: 'python project.py'.
8. Access and test this application by visiting http://localhost:8000 locally

<h1> Usage </h1>

<ul>
	<li> 1. Sign in with Google+ or Facebook account </li>
	<li> 2. Add a room </li>
	<li> 3. Edit or Delete the room </li>
	<li> 4. Add a storage and a description what will be stored in that storage </li>
	<li> 5. Edit or delete storages </li>
	<li> 6. Sign in as another user to see that there is no access to delete or edit items created by another user. </li>
</ul>

<h1> Technical Requirements </h1>

<ul>
	<li> Python 2.7.6 </li>
	<li> Flask 0.10.1 </li>
	<li> SQLAlchemy 0.8.4 </li>
	<li> httplib2 0.9.1 </li>

</ul>


