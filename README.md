# URLAnalysis - A Machine Learning-Based Phishing Detection System 

## Building
* Ensure [Docker Desktop](https://www.docker.com/products/docker-desktop/) and [git](https://github.com/git-guides/install-git) are installed 
* Open terminal (mac) or powershell (windows), and change to directory where project should be downloaded
* Clone this repository: `git clone repo-url`
* Change directory to base of repo
* Create file called `.env` with the following text: `pg_pw = pass` where pass is the password you would like to use
* Run `docker compose up`

## Accessing
* JupyterLab
  * Access web interface [here](http://localhost:8888)
  * Password: in .env file
* Postgres
  * DB Name: phishing_data
  * User: daan
  * Password: in .env file
  * Host/Port: localhost:5432