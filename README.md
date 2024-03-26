# HezaWorks API
## Background information
This project serves as the backend API for my webstack portfolio project built during my learning journey in the [ALX](https://www.alxafrica.com) Software Engineering programme to showcase my skills gained at the end of the program. This project summarizes my ability to execute a complete Software Development Cycle stages. I handled the Planning, Development/Building, Testing, Deployment, Testing and Production as well as future Maintenance of this awesome software application.

More details on the inspiration to this project as well as a detailed tech stack leveraged, visit the below links where I wrote a blog on my journey and experience on this project.
- [Medium](https://github.com/felixayot/ALX_SE_important_concepts/blob/master/custopedia.md)
- [LinkedIn](https://github.com/felixayot/ALX_SE_important_concepts/blob/master/custopedia_mvp_specification.md)

## Tech stack overview
Below is a brief overview of the tech stack leveraged to bring this API to life.

- `Flask-Python3`
- `SQLite` for development and `MySQL` for production.
- `nginx` webserver for static data and `gunicorn` for serving the dynamic application contents.

For the Frontend tech stack, visit this repository for a detailed overview: [HezaWorks Application](https://github.com/felixayot/hezaworks-app)


# Installation
### Prerequisites
- Ubuntu 20.04 LTS - Operating system required.

This project was developed and tested on an `Ubuntu 20.04 LTS` terminal. Using other Ubuntu versions may result in some incompatibility issues. If you're not on an Ubuntu 20.04 LTS terminal/os/VM, I'd suggest using a `docker` container spinning the Ubuntu 20.04 LTS image for full functionality of the app.

- Python3 - Installed in your local terminal/vagrant/VM/docker container

### Getting started
Clone the repository to your local terminal, Ubuntu 20.04 LTS remember, then create a virtual environment using:
`Python3 -m venv venv` then launch that virtual environment while you're in the repo's root directory with this command:
`source venv/bin/activate`. You'll need this virtual environment to run the application successfully with all it's required packages without affecting any of your previously globally installed packages in your local machine.
#### NOTE:
You will have to configure the environment variables with your own values in order to run the application. 

Once you're in the virtual environment, you can install the rest of the packages required to run the application located in the `requirements.txt` file. Use this command:
`pip install -r requirements.txt` 


# Usage

Now you're ready to start running the application locally(in the development server) in your machine.
You can run it using either of these two commands:
  - `Python run.py` or
  - `flask run`
It'll be listening on port 5000 by default. You can browse it in your browser to have a look at the various consumable endpoints.

At this point, you can now use your favourite API testing platform like `Postman`, `Insomnia`, `HTTPie` et cetera to test the various accessible endpoints.


# Contribution

All contributions to help improve the API features and functionalities are welcome. Fork the repository and create a pull request with your modifications. I'll be sure to review them.


# Authors

- Felix Ayot - [Github](https://github.com/felixayot) / [LinkedIn](https://www.linkedin.com/in/felixayot) / [X](https://twitter.com/felix_ayot)  


# License🧾📜

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
