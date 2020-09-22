const { User } = require('../models/User');

let auth = (req, res, next) => {

    // 인증 처리르 하는 곳

    // client cookie에서 token을 가져옴
    let token = req.cookies.x_auth;

    // decode token -> user 찾기
    User.findByToken(token, (err,user) => {
        // user이 있으면 인증 okay
        // user이 없으면 인증 no!
        
        if(err) throw err;
        if(!user) return res.json({isAuth: false, error: true })

        req.token = token;
        req.user = user;
        next();
    })

    
}

module.exports = { auth };