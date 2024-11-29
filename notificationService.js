const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
const serviceAccount = require('C:/Users/admin/Downloads/react-native-app-8b283-firebase-adminsdk-5jj6x-e268f24026.json'); // Replace with your service account file path

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

async function sendNotificationToDevice(deviceId, message) {
    try {
        const payload = {
            notification: {
                title: 'New Notification',
                body: message,
            },
        };

        // Send the notification to the device
        const response = await admin.messaging().sendToDevice(deviceId, payload);

        console.log('Notification sent successfully:', response);
        return true;  // Indicating success
    } catch (error) {
        console.error('Error sending notification:', error);
        return false;  // Indicating failure
    }
}

module.exports = sendNotificationToDevice;
