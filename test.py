import unittest
from unittest.mock import MagicMock
from unittest.mock import patch


class TestChatServer(unittest.TestCase):

    def setUp(self):
       
        self.mongo_client_patch = patch('your_chat_server_script.py.MongoClient')
        self.mongo_client_mock = self.mongo_client_patch.start()

       
        self.mongo_collection_mock = MagicMock()
        self.mongo_collections = {
            'config.student': self.mongo_collection_mock,
            'config.online_list': self.mongo_collection_mock,
            'config.available_rooms': self.mongo_collection_mock,
        }

        self.mongo_client_mock.return_value.__getitem__.side_effect = lambda name: self.mongo_collections[name]

    def tearDown(self):
       
        self.mongo_client_patch.stop()

    def test_authenticate(self):
      
        self.assertTrue(authenticate("test_user", "test_password", "127.0.0.1", 12345))
        self.assertFalse(authenticate("nonexistent_user", "wrong_password", "127.0.0.1", 12345))

    def test_register_user(self):
       
        self.assertTrue(register_user("new_user", "new_password", "127.0.0.1", 12345)[0])
        self.assertFalse(register_user("existing_user", "existing_password", "127.0.0.1", 12345)[0])

    def test_list_online_users(self):

        py.MongoClient = MagicMock()
        py.MongoClient.return_value.__getitem__.return_value.find.return_value = [
            {"username": "user1"},
            {"username": "user2"}
        ]
        result = list_online_users()
        self.assertEqual(result, [{"username": "user1"}, {"username": "user2"}])

    def test_list_rooms(self):
        
        py.MongoClient = MagicMock()
        py.MongoClient.return_value.__getitem__.return_value.find.return_value = [
            {"Room_name": "room1"},
            {"Room_name": "room2"}
        ]
        result = list_rooms()
        self.assertEqual(result, [{"Room_name": "room1"}, {"Room_name": "room2"}])

        def test_list_ips(self):
      
         self.mongo_collections['config.online_list'].find.return_value = [
            {"client_ip": "127.0.0.1", "client_port": 12345},
            {"client_ip": "192.168.0.1", "client_port": 54321},
        ]

        result = list_ips()

        
        self.assertEqual(result, [{"client_ip": "127.0.0.1", "client_port": 12345},
                                  {"client_ip": "192.168.0.1", "client_port": 54321}])

    def test_add_member(self):
        client_socket_mock = MagicMock()
        room_mock = Room('test_room')

        room_mock.add_member(client_socket_mock, 'test_username')

 
        self.assertEqual(room_mock.members, [(client_socket_mock, 'test_username')])



    def test_remove_member(self):
        client_socket_mock = MagicMock()
        room_mock = Room('test_room')
        room_mock.add_member(client_socket_mock, 'test_username')

        room_mock.remove_member(client_socket_mock)

       
        self.assertEqual(room_mock.members, [])

    def test_handle_room_messages(self):
        client_socket_mock = MagicMock()
        client_socket_mock.recv.return_value.decode.return_value = 'test_message'

        room_mock = Room('test_room')
        room_mock.broadcast_message = MagicMock()

        handle_room_messages(room_mock, 'test_username', client_socket_mock)

       
        room_mock.broadcast_message.assert_called_once_with('test_message', 'test_username')


if __name__ == '__main__':
    unittest.main()
