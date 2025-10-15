import User from "../models/User.js"
import FriendRequest from "../models/FriendRequest.js"

export async function getRecommendedUsers(req, res) {
    try {
        const currentUserId = req.user.id
        const currentUser = await User.findById(currentUserId)

        const recommendedUser = await User.find({
            $and: [
                { _id: { $ne: currentUserId } }, // exclude current user
                { _id: { $nin: currentUser.friends } }, // ✅ Fixed: was $id, now _id and $nin
            ]
        }).limit(20) // ✅ Added limit for performance

        res.status(200).json(recommendedUser)
    } catch (error) {
        console.log("Error in getRecommendedUser", error)
        res.status(500).json({ message: "Internal server error" })
    }
}

export async function getMyFriends(req, res) {
    try {
        const user = await User.findById(req.user.id)
            .select("friends")
            .populate("friends", "fullName profilePic nativeLanguage learningLanguage")
        res.status(200).json(user.friends)
    } catch (error) {
        console.log("Error in getMyFriends controller", error)
        res.status(500).json({ message: "Internal server error" })
    }
}

export async function sendFriendRequest(req, res) {
    try {
        const myId = req.user.id
        const { id: recipientId } = req.params

        // prevent request to yourself
        if (myId === recipientId) {
            return res.status(400).json({ message: "you can't send request to yourself" })
        }

        const recipient = await User.findById(recipientId)
        if (!recipient) {
            return res.status(400).json({ message: "Recipient Not Found" })
        }

        // check if user is already friends   
        if (recipient.friends.includes(myId)) {
            return res.status(400).json({ message: "you already friends with this user" })
        }

        // check if a req already exists   
        const existFriendRequest = await FriendRequest.findOne({
            $or: [
                { sender: myId, recipient: recipientId },
                { sender: recipientId, recipient: myId },
            ]
        })

        if (existFriendRequest) {
            return res.status(400).json({ message: "A friend request already exists between you and this user" })
        }

        const friendRequest = await FriendRequest.create({
            sender: myId,
            recipient: recipientId,
        })

        res.status(201).json(friendRequest)
    } catch (error) {
        console.error("Error in Send friend request", error.message)
        res.status(500).json({ message: "Internal server error" })
    }
}

export async function acceptFriendRequest(req, res) {
    try {
        const { id: requestId } = req.params

        const friendRequest = await FriendRequest.findById(requestId)
        if (!friendRequest) {
            return res.status(404).json({ message: "Friend request not found" })
        }

        // verify the current user is the recipient
        if (friendRequest.recipient.toString() !== req.user.id) {
            return res.status(403).json({ message: "You are not authorized to accept request" })
        }

        friendRequest.status = "accepted"
        await friendRequest.save()

        // add each users to the other's friends array
        await User.findByIdAndUpdate(friendRequest.sender, {
            $addToSet: { friends: friendRequest.recipient }
        })

        await User.findByIdAndUpdate(friendRequest.recipient, {
            $addToSet: { friends: friendRequest.sender }
        })

        res.status(200).json({ message: "Friend request accepted" })
    } catch (error) {
        console.error("Error in acceptfriendrequest", error.message)
        res.status(500).json({ message: "Internal server error" })
    }
}

export async function getFriendRequest(req, res) {
    try {
        const incomingReqs = await FriendRequest.find({
            recipient: req.user.id,
            status: "pending",
        }).populate("sender", "fullName profilePic nativeLanguage learningLanguage")

        const acceptedReqs = await FriendRequest.find({
            sender: req.user.id,
            status: "accepted",
        }).populate("recipient", "fullName profilePic") // ✅ Fixed typo: recipent -> recipient

        res.status(200).json({ incomingReqs, acceptedReqs }) // ✅ Fixed: return as object
    } catch (error) {
        console.error("Error in getPendingFriendrequest", error.message)
        res.status(500).json({ message: "Internal server error" })
    }
}

export async function getOutgoingFriendRequest(req, res) {
    try {
        const outgoingRequest = await FriendRequest.find({
            sender: req.user.id,
            status: "pending"
        }).populate("recipient", "fullName profilePic nativeLanguage learningLanguage")
        res.status(200).json(outgoingRequest)
    } catch (error) {
        console.error("Error in getOngoingFriendrequest controller", error.message)
        res.status(500).json({ message: "Internal server error" })
    }
}