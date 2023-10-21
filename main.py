from app import User, db, app

with app.app_context():
    user = User(name="Eldar", email="zanizdra.eldar@gmail.com", password='', role='admin')
    password = 'Macintosh1960!'

    hashed_password = user.generate_cache(password)

    db.session.add(user)
    db.session.commit()



