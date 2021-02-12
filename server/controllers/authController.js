const bcrypt = require('bcrypt');

module.exports = {
  register: async (req, res) => {
    const { username, password, isAdmin } = req.body;
    const db = req.app.get('db');
    const result = await db.get_user([username]);
    const existingUser = result[0];
    if (existingUser) {
      return res.status(409).send('Username taken');
    }
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const registeredUser = await db.register_user([isAdmin, username, hash]);
    const user = registeredUser[0];
    req.session.user = { isAdmin: user.is_admin, username: user.username, id: user.id };
    return res.status(201).send(req.session.user);
  },
  login: async (req, res) =>{
    const { username, password } = req.body
    const db = req.app.get('db')
    const foundUser = await db.get_user([username])
    const user = foundUser[0]
    if(!user){
        return res.send(401).send(`User not found. Please register as a new user before logging in.`)
    }
    const isAuthenticated = bcrypt.compareSync(password, user.hash)
    if(!isAuthenticated){
        return res.send(403).send(`Incorrect password.`)
    } else {
        req.session.user = {isAdmin: user.is_admin, username: user.username, id: user.id}
        return res.status(200).send(req.session.user)
    }
  },
  logout: async (req, res)=>{
      req.session.destroy()
      return res.sendStatus(200)
  }
};






// const bcrypt = require('bcrypt')

// module.exports ={
//     register: async (req, res)=>{
//         //req.body comes from the user
//         const {username, password, isAdmin} = req.body
//         //we get the db instance to pull the db information
//         const db = req.app.get('db')
//         //in order to use await we set it to a variable call the function get_user from the db and pass in username as the argument


//         //username is coming from the user.
//         //array is sent as 1 item to th db. it's send through the array since we can only send 1 item at a time to the db but we may be checking multiple values or key pairs in an object. when we use express the [] are not requiredbut we may not always be using express
//         let result = await db.get_user([username])
//         //response from db is always an array and results is the reponse we got from line 18 so results is also an array and we are pulling the first value from results which in this case is the returned username that matches our request
//         //IF THERE IS ONE
//         let existingUser = result[0]
//         //IF THERE WAS NOT A MATCHING VALUE FOR THE REQUEST the below value would be falsy
//         //IF THERE WAS A MATCHING VALUE then the request is truthy and it gives us a return 
//         if(existingUser){
//             return res.status(409).send(`Username taken`)
//         }
//         //if the username hasn't been taken we create a hash password
//         const salt = bcrypt.genSaltSync(10)
//         const hash = bcrypt.hashSync(password, salt)
//         //next we are going to create the user
//         //Similar to line 17 we are taking the information from the user and sending it to our db as an array so that it can INSERT INTO the table the user input the result gets assigned to registeredUser which is an array
//         const registeredUser = await db.register_user([isAdmin, username, hash])
//         //to make our code cleaner we assign it to a variable so user is an Array within an array and is returning the user input which has not been formated and added to our table
//         let user = registeredUser[0]
//         //here we take those new values that were put into our db  and assign them to a session for user. these names have to match what we used in our db. so we are digging into registeredUser[0].is_admin which is equal to isAdmin user input
//         req.session.user={
//             isAdmin: user.is_admin,
//             username: user.username,
//             id: user.id
//         }
//         //here we return the session information
//         return res.status(201).send(req.session.user)
//     }
// }