const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10
const jwt = require('jsonwebtoken');


const userSchema = mongoose.Schema({
    name:{
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

// index.js의 users.save 전에 실행됨
userSchema.pre('save', function( next ){

    var user = this;

    if(user.isModified('password')){

         //비밀번호를 암호화시킴
         bcrypt.genSalt(saltRounds, function(err, salt){
            if(err) return next(err);
 
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err)
                user.password = hash
                next()
             })
        })
    }else{
        next()
    }

})

userSchema.methods.comparePassword = function(plainPassword, cb){

    // plainPassword 1234567
    // 암호화된 비밀번호 $2b$10$tXGcjUo9zIaBFW.wlY4pQOQU0jan9nNfzq1jIKFPcc4wlZmndEhXO
    // 같은지 확인해야 함
    // plainPassword를 암호화해서 비교한다
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err)
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb){
    var user = this;

    //jsonwebtoken을 이용해서 token을 생성
    jwt.sign(user._id.toHexString(), 'secretToken')

    var token = user._id + 'secretToken'
    user.token = token
    user.save(function(err, user){
        if(err) return cb(err)
        cb(null, user)
    })
}

const User = mongoose.model('User', userSchema)

module.exports = {User}