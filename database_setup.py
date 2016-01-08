import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Storage(Base):
    __tablename__ = 'storage'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
        }

class SubStorage(Base):
    __tablename__ = 'substorage'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)    
    description = Column(String(250))
    storage_id = Column(Integer, ForeignKey('storage.id'))
    storage = relationship(Storage)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id,
            'description': self.description,
        }

class SubStorageItem(Base):
    __tablename__ = 'substorage_item'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    locatedplace = Column(String(250))
    substorage_id = Column(Integer, ForeignKey('substorage.id'))
    substorage = relationship(SubStorage)

# We added this serialize function to be able to send JSON objects in a
# serializable format
    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'locatedplace': self.locatedplace,
        }


engine = create_engine('sqlite:///storageappwithusers.db')

Base.metadata.create_all(engine)