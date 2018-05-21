class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  def authenticate_api!
    email = request.headers['HTTP_X_USER_EMAIL']
    token = request.headers['HTTP_X_API_TOKEN']
    @current_user = User.where(email: email).take
    unless @current_user && @current_user.api_token == token
      head 401
    end
  end
end
