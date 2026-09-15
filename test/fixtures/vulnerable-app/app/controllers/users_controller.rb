class UsersController < ApplicationController
  before_action :authenticate_user!

  def index
    @users = User.where("role = '#{params[:role]}'")
    render :index
  end

  def create
    @user = User.create(params[:user])
    redirect_to @user
  end

  def show
    @user_bio = "<%= raw params[:bio] %>"
  end
end
