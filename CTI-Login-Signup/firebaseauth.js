import { initializeApp } from "https://www.gstatic.com/firebasejs/11.3.1/firebase-app.js";
import { getAnalytics } from "https://www.gstatic.com/firebasejs/11.3.1/firebase-analytics.js";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, sendPasswordResetEmail } from "https://www.gstatic.com/firebasejs/11.3.1/firebase-auth.js";
import { getFirestore, setDoc, doc } from "https://www.gstatic.com/firebasejs/11.3.1/firebase-firestore.js";

 
  const firebaseConfig = {
    apiKey: "AIzaSyBrHISeGsrYEh5HiyWoc2tmfC-FnzsM4FI",
    authDomain: "cyart-07.firebaseapp.com",
    projectId: "cyart-07",
    storageBucket: "cyart-07.firebasestorage.app",
    messagingSenderId: "1078718904149",
    appId: "1:1078718904149:web:3c6c0b402e1e366385a1dc",
    measurementId: "G-9BTGF2P85L"
  };

  // Initialize Firebase
  const app = initializeApp(firebaseConfig);
  const analytics = getAnalytics(app);

  function showMessage(message, divId){
    var messageDiv=document.getElementById(divId);
    messageDiv.style.display="block";
    messageDiv.innerHTML=message;
    messageDiv.style.opacity=1;
    setTimeout(function(){
        messageDiv.style.opacity=0;
    },5000);
 }

 // Sign-Up Handler

 const signUp=document.getElementById('submitSignUp');
 signUp.addEventListener('click', (event)=>{
    event.preventDefault();
    const email=document.getElementById('rEmail').value;
    const password=document.getElementById('rPassword').value;
    const firstName=document.getElementById('fName').value;
    const lastName=document.getElementById('lName').value;

    const auth=getAuth();
    const db=getFirestore();

    createUserWithEmailAndPassword(auth, email, password)
    .then((userCredential)=>{
        const user=userCredential.user;
        const userData={
            email: email,
            firstName: firstName,
            lastName:lastName
        };
        showMessage('Account Created Successfully', 'signUpMessage');
        
        const docRef=doc(db, "users", user.uid);
        setDoc(docRef,userData)
        .then(()=>{
            window.location.href='login.html';
        })
        .catch((error)=>{
            console.error("Error Writing Document", error);

        });
    })
    .catch((error)=>{
        const errorCode=error.code;
        if(errorCode=='auth/email-already-in-use'){
            showMessage('Email Address Already Exists !!!', 'signUpMessage');
        }
        else{
            showMessage('Unable to create User', 'signUpMessage');
        }
    })
 });

 // Sign-In Handler

 const signIn=document.getElementById('submitSignIn');
 signIn.addEventListener('click', (event)=>{
    event.preventDefault();
    const email=document.getElementById('email').value;
    const password=document.getElementById('password').value;
    const auth=getAuth();

    signInWithEmailAndPassword(auth, email, password)
  .then((userCredential) => {
    showMessage('Login is successful', 'signInMessage');

    // Confetti effect
    var end = Date.now() + (3 * 1000); // 3 seconds
    var colors = ['#bb0000', '#ffffff'];

    (function frame() {
      confetti({
        particleCount: 2,
        angle: 60,
        spread: 55,
        origin: { x: 0 },
        colors: colors
      });
      confetti({
        particleCount: 2,
        angle: 120,
        spread: 55,
        origin: { x: 1 },
        colors: colors
      });

      if (Date.now() < end) {
        requestAnimationFrame(frame);
      } else {
        // Redirect after the confetti effect has finished
        const user = userCredential.user;
        localStorage.setItem('loggedInUserId', user.uid);
        window.location.href = 'http://127.0.0.1:5500/index.html';
      }
    }());
  })
    .catch((error)=>{
        const errorCode=error.code;
        if(errorCode==='auth/invalid-credential'){
            showMessage('Incorrect Email or Password', 'signInMessage');
        }
        else{
            showMessage('Account does not Exist', 'signInMessage');
        }
    })
 })


 // Forgot Password Handler

 const forgotPassword = document.getElementById('forgot-password');
 forgotPassword.addEventListener('click', (event) => {
   event.preventDefault();
   const email = prompt("Please enter your email address to reset the password:");
   const auth = getAuth();
 
   if (email) {
     sendPasswordResetEmail(auth, email)
       .then(() => {
         showMessage('Password reset email sent! Please check your inbox.', 'signInMessage');
       })
       .catch((error) => {
         const errorCode = error.code;
         if (errorCode === 'auth/user-not-found') {
           showMessage('No account found with this email.', 'signInMessage');
         } else {
           showMessage('Error sending password reset email.', 'signInMessage');
         }
       });
   }
 });
