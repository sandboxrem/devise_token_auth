## Single vs Multiple authentication methods per resource
By default, `devise_token_auth` only allows a single authentication per resource.
What does this mean? Let's take the example of having a Customer model and you want to let people sign up with Facebook or with their email address. If they register with their Facebook account, then you'll have one row in your `customers` table, and if they then register with their email address, you'll have **another** row in your `customers` table. Both for the same real life person.
This is because multiple sign in methods for a single resource are difficult to maintain and reason about, particularly when trying to build a suitable UX. The only problem is the expectation that users will always use the same authentication method.
BUT, `devise_token_auth` is awesome enough (like `devise`) to let you manage multiple methods on a single resource without sacrificing your data integrity.  Using our previous example, this means you can have a single Customer row which can be authenticated with **either** Facebook **or** their email address.
### Setting up single authentication per resource (default behaviour)
When you run `rails g devise_token_auth:install User auth`, you will have a migration setup which will look something like this:
~~~ruby
# db/migrate/20151116175322_add_devise_token_auth_fields_to_users.rb
class AddDeviseTokenAuthFieldsToUsers < ActiveRecord::Migration
  t.string :provider, :null => false, :default => "email"
  t.string :uid, :null => false, :default => ""
  ...
end
~~~
The `provider` and `uid` fields are used to record what method and what identifier we will use for identifying and authing a `User`. For example:
| Signup method | provider | uid |
|---|---|---|
| email: bob@home.com | email | bob@home.com |
| facebook user id: 12345 | facebook | 12345 |
And that's pretty much all you have to do!
**The good thing** about this method is that it's simplest to implement from a UX point of view and, consequently, the most common implementation you'll see at the moment.
**The problem** is that you may end up with a single person creating multiple accounts when they don't mean to because they've forgotten how they originally authenticated. In order to make this happen, the gem has to be fairly opinionated about how to manage your domain objects (e.g. it allows multiple users with the same "email" field)
### Setting up multiple authentication methods per resource
You may want to let a user log in with multiple methods to the same account. In order to do this, the `devise_token_auth` gem is unopinionated on how you've built your model layer, and just requires that you declare how to look up various resources.
If using this methodology, you **do not need provider/uid columns on your resource table**, so you can remove these from the generated migration when running `rails g devise_token_auth:install`.
Instead, you need to register finder methods defining how to get to your resource from a particular provider. If you don't register one, it falls back to the default behaviour for single authentication of querying provider/uid (if those columns exist).
An example of registering these finders is done as follows:
~~~ruby
class User < ActiveRecord::Base
  # In this example, the twitter id is simply stored directly on the User
  resource_finder_for :twitter,  ->(twitter_id)  { find_by(twitter_id: twitter_id) }
   # In this example, the external facebook user is modelled seperately from the
  # User, and we need to go through an association to find the User to
  # authenticate against
  resource_finder_for :facebook, ->(facebook_id) { FacebookUser.find_by(facebook_id: facebook_id).user }
end
~~~
You'll need to register a finder for each authentication method you want to allow users to have. Given a specific `uid` (for omniauth, this will most likely be the foreign key onto the third party object). You can register a `Proc` or a `Lambda` for this, and each time we get a request which has been authed in this manner, we will look up using it.
**WARNING**: Bear in mind that these finder methods will get called on every authenticated request. So consider performance carefully. For example, with the `:facebook` finder above, we may want to add an `.includes(:user)` to keep the number of DB queries down.
#### Default finders when using multiple authentication
You don't need to define a `resource_finder_for` callback for something registered as a `Devise.authentication_key` (e.g. `:email` or `:username`, see the [Devise wiki](https://github.com/plataformatec/devise/wiki/How-To:-Allow-users-to-sign-in-using-their-username-or-email-address#user-content-tell-devise-to-use-login-in-the-authentication_keys)), then we will call a `find_by` using that column. Consequently:
~~~ruby
class Users < ActiveRecord::Base
  # We are allowing users to authenticating with either their email or username
  devise :database_authenticatable, authentication_keys: [:username, :email]
   # Therefore, we don't need the following:
  # resource_finder_for :username, ->(username) { find_by(username: username) }
end
~~~
