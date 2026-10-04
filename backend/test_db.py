# -*- coding: utf-8 -*-
print('Hola mundo')
from app.database import test_connection
print(f'Conexión DB: {test_connection()}')
